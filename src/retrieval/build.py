"""Dynamic orchestration for validation, canonical document builds, and hybrid indices."""

import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from src.retrieval.config import (
    ASVS_RAW_DIR,
    CWE_RAW_PATHS,
    DOCUMENTS_PATH,
    EXAMPLES_DIR,
    KNOWLEDGE_BASE_DIR,
    MANIFEST_PATH,
    QDRANT_COLLECTION_NAME,
    QDRANT_STORAGE_DIR,
    SCHEMA_PATH,
    SCHEMA_VERSION,
    SEMGREP_RAW_DIR,
)
from src.retrieval.chunking.markdown_chunker import DocumentChunk, MarkdownSectionChunker
from src.retrieval.embeddings.client import EmbeddingClient
from src.retrieval.exceptions import DuplicateDocumentIdError, SourceValidationError
from src.retrieval.models import KnowledgeDocument
from src.retrieval.vector.qdrant_store import QdrantVectorStore
from src.retrieval.parsers.asvs_parser import parse_asvs_csv
from src.retrieval.parsers.cwe_parser import CweParseResult, parse_cwe_views
from src.retrieval.parsers.example_parser import parse_example_directory
from src.retrieval.parsers.semgrep_rule_parser import parse_semgrep_rules_directory
from src.retrieval.parsers.unified_markdown_parser import parse_all_markdown_sources
from src.retrieval.storage.jsonl_store import atomic_write_bytes, serialize_documents, sha256_bytes
from src.retrieval.validation import build_knowledge_validator, load_knowledge_schema, validate_document
from src.retrieval.vector.qdrant_store import QdrantVectorStore


@dataclass(frozen=True)
class CollectionResult:
    """Validated documents, warnings, and input statistics from all sources."""

    documents: list[KnowledgeDocument]
    warnings: list[str]
    input_records: dict[str, int]


@dataclass(frozen=True)
class BuildResult:
    """Paths and deterministic metadata produced by a canonical build."""

    documents_path: Path
    manifest_path: Path
    document_count: int
    documents_sha256: str
    warnings: list[str]


class DocumentRegistry:
    """Reject duplicate normalized IDs across every source family."""

    def __init__(self) -> None:
        self._documents: dict[str, KnowledgeDocument] = {}

    def add(self, document: KnowledgeDocument) -> None:
        """Register one document or fail with both provenance paths."""
        previous = self._documents.get(document.doc_id)
        if previous is not None:
            raise DuplicateDocumentIdError(
                f"Duplicate ID {document.doc_id}: first source {previous.source.raw_path}; "
                f"conflicting source {document.source.raw_path}"
            )
        self._documents[document.doc_id] = document

    def documents(self) -> list[KnowledgeDocument]:
        """Return registered documents in deterministic ID order."""
        return [self._documents[key] for key in sorted(self._documents)]


def collect_documents() -> CollectionResult:
    """Dynamically parse, validate, and register 100% of all configured raw knowledge sources."""
    warnings: list[str] = []
    registry = DocumentRegistry()
    validator = build_knowledge_validator(load_knowledge_schema(SCHEMA_PATH))

    # 1. CWE Views
    cwe_result: CweParseResult = parse_cwe_views(CWE_RAW_PATHS)
    for doc in cwe_result.documents:
        validate_document(doc, validator)
        registry.add(doc)

    # 2. OWASP ASVS Requirements (CSV)
    asvs_csv = ASVS_RAW_DIR / "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv"
    if asvs_csv.is_file():
        asvs_docs = parse_asvs_csv(asvs_csv)
        for doc in asvs_docs:
            validate_document(doc, validator)
            registry.add(doc)

    # 3. Semgrep Rules (YAML)
    semgrep_rules_dir = SEMGREP_RAW_DIR / "rules"
    if semgrep_rules_dir.is_dir():
        rules = parse_semgrep_rules_directory(semgrep_rules_dir)
        for doc in rules:
            validate_document(doc, validator)
            registry.add(doc)

    # 4. Curated Vulnerability Examples (YAML)
    if EXAMPLES_DIR.is_dir():
        examples = parse_example_directory(EXAMPLES_DIR)
        for doc in examples:
            validate_document(doc, validator)
            registry.add(doc)

    # 5. Unified Markdown Ingestion (100% of all Markdown in raw/)
    # Covers OWASP Top 10 (2017/2021/2025), ZAP Alerts & Guides, Cheatsheets, CodeQL, Semgrep docs/vulns, ASVS docs
    raw_root = KNOWLEDGE_BASE_DIR / "raw"
    if raw_root.is_dir():
        md_docs, md_warnings = parse_all_markdown_sources(raw_root)
        warnings.extend(md_warnings)
        for doc in md_docs:
            validate_document(doc, validator)
            registry.add(doc)

    documents = registry.documents()
    if not documents:
        raise SourceValidationError("Knowledge base collection produced 0 documents.")

    counts = Counter(document.doc_type for document in documents)
    return CollectionResult(
        documents=documents,
        warnings=warnings,
        input_records={
            "total_documents": len(documents),
            "cwe_documents": len(cwe_result.documents),
            **{f"{k}_count": v for k, v in counts.items()},
        },
    )


def build_manifest(collection: CollectionResult, documents_sha256: str) -> dict[str, object]:
    """Build deterministic manifest metadata without timestamps."""
    counts = Counter(document.doc_type for document in collection.documents)
    return {
        "schema_version": SCHEMA_VERSION,
        "document_count": len(collection.documents),
        "documents_sha256": documents_sha256,
        "sources": dict(sorted(counts.items())),
        "input_records": collection.input_records,
    }


def build_documents(
    documents_path: Path = DOCUMENTS_PATH,
    manifest_path: Path = MANIFEST_PATH,
) -> BuildResult:
    """Build canonical JSONL and manifest from all raw and curated sources."""
    collection = collect_documents()
    serialized = serialize_documents(collection.documents)
    digest = sha256_bytes(serialized)
    manifest = build_manifest(collection, digest)
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write_bytes(documents_path, serialized)
    atomic_write_bytes(manifest_path, manifest_bytes)
    return BuildResult(
        documents_path=documents_path,
        manifest_path=manifest_path,
        document_count=len(collection.documents),
        documents_sha256=digest,
        warnings=collection.warnings,
    )


def build_vector_index(
    documents: list[KnowledgeDocument] | None = None,
    qdrant_storage_path: Path = QDRANT_STORAGE_DIR,
    collection_name: str = QDRANT_COLLECTION_NAME,
) -> int:
    """Generate section-aware child chunks and upsert their dense embeddings into Qdrant.

    Args:
        documents: Optional pre-loaded list of parent KnowledgeDocument objects.
        qdrant_storage_path: Directory path for Qdrant vector database persistence.
        collection_name: Collection identifier within Qdrant.

    Returns:
        Total number of child chunks indexed into the vector store.
    """
    if documents is None:
        from src.retrieval.storage.jsonl_store import read_documents

        if not DOCUMENTS_PATH.is_file():
            build_documents()
        documents = read_documents(DOCUMENTS_PATH)

    chunker = MarkdownSectionChunker()
    all_chunks: list[DocumentChunk] = []
    for doc in documents:
        all_chunks.extend(chunker.chunk_document(doc))

    client = EmbeddingClient()
    passages = [chunk.content for chunk in all_chunks]
    embeddings = client.embed_texts(passages)
    dim = len(embeddings[0]) if embeddings else int(os.getenv("EMBEDDING_DIMENSION", "1536"))

    store = QdrantVectorStore(storage_path=qdrant_storage_path, collection_name=collection_name, dimension=dim)
    store.init_collection(recreate=True)
    store.upsert_chunks(all_chunks, embeddings)
    return len(all_chunks)
