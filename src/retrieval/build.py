"""Dynamic orchestration for validation, canonical document builds, and hybrid indices."""

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from src.retrieval.config import (
    ASVS_RAW_DIR,
    CHEATSHEETS_RAW_DIR,
    CODEQL_RAW_DIR,
    CWE_RAW_PATHS,
    DOCUMENTS_PATH,
    EXAMPLES_DIR,
    MANIFEST_PATH,
    OWASP_TOP_TEN_DIR,
    QDRANT_COLLECTION_NAME,
    QDRANT_STORAGE_DIR,
    SCHEMA_PATH,
    SCHEMA_VERSION,
    SEMGREP_RAW_DIR,
    ZAP_RAW_DIR,
)
from src.retrieval.embeddings.client import EmbeddingClient
from src.retrieval.exceptions import DuplicateDocumentIdError, SourceValidationError
from src.retrieval.models import KnowledgeDocument
from src.retrieval.parsers.asvs_parser import parse_asvs_csv
from src.retrieval.parsers.cheatsheet_parser import parse_cheatsheet_directory
from src.retrieval.parsers.cwe_parser import CweParseResult, parse_cwe_views
from src.retrieval.parsers.example_parser import parse_example_directory
from src.retrieval.parsers.markdown_doc_parser import parse_generic_markdown_directory
from src.retrieval.parsers.owasp_parser import parse_owasp_directory
from src.retrieval.parsers.semgrep_rule_parser import parse_semgrep_rules_directory
from src.retrieval.parsers.zap_alert_parser import parse_zap_alerts_directory
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

    # 2. OWASP Top 10 (Multi-version: 2025, 2021, 2017)
    owasp_docs, owasp_warnings = parse_owasp_directory(OWASP_TOP_TEN_DIR)
    warnings.extend(owasp_warnings)
    for doc in owasp_docs:
        validate_document(doc, validator)
        registry.add(doc)

    # 3. OWASP ASVS Requirements
    asvs_csv = ASVS_RAW_DIR / "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv"
    if asvs_csv.is_file():
        asvs_docs = parse_asvs_csv(asvs_csv)
        for doc in asvs_docs:
            validate_document(doc, validator)
            registry.add(doc)

    # 4. OWASP Cheat Sheets
    if CHEATSHEETS_RAW_DIR.is_dir():
        cheatsheets = parse_cheatsheet_directory(CHEATSHEETS_RAW_DIR)
        for doc in cheatsheets:
            validate_document(doc, validator)
            registry.add(doc)

    # 5. Semgrep Rules
    semgrep_rules_dir = SEMGREP_RAW_DIR / "rules"
    if semgrep_rules_dir.is_dir():
        rules = parse_semgrep_rules_directory(semgrep_rules_dir)
        for doc in rules:
            validate_document(doc, validator)
            registry.add(doc)

    # 6. OWASP ZAP Alerts
    zap_alerts_dir = ZAP_RAW_DIR / "alerts"
    if zap_alerts_dir.is_dir():
        alerts = parse_zap_alerts_directory(zap_alerts_dir)
        for doc in alerts:
            validate_document(doc, validator)
            registry.add(doc)

    # 7. CodeQL Documentation
    if CODEQL_RAW_DIR.is_dir():
        codeql_docs = parse_generic_markdown_directory(
            CODEQL_RAW_DIR,
            source_name="CodeQL Documentation",
            doc_type="scanner_document",
            doc_id_prefix="codeql-doc",
            extra_tags=["codeql", "sast", "data-flow"],
        )
        for doc in codeql_docs:
            validate_document(doc, validator)
            registry.add(doc)

    # 8. Semgrep Vulnerability Guides & Docs
    semgrep_vulns_dir = SEMGREP_RAW_DIR / "vulnerabilities"
    if semgrep_vulns_dir.is_dir():
        vuln_guides = parse_generic_markdown_directory(
            semgrep_vulns_dir,
            source_name="Semgrep Vulnerability Guides",
            doc_type="scanner_document",
            doc_id_prefix="semgrep-vuln",
            extra_tags=["semgrep", "vulnerability-guide"],
            recursive=True,
        )
        for doc in vuln_guides:
            validate_document(doc, validator)
            registry.add(doc)

    semgrep_docs_dir = SEMGREP_RAW_DIR / "docs"
    if semgrep_docs_dir.is_dir():
        semgrep_docs = parse_generic_markdown_directory(
            semgrep_docs_dir,
            source_name="Semgrep Documentation",
            doc_type="scanner_document",
            doc_id_prefix="semgrep-doc",
            extra_tags=["semgrep", "docs"],
        )
        for doc in semgrep_docs:
            validate_document(doc, validator)
            registry.add(doc)

    # 9. OWASP ZAP Docker Guides
    zap_docker_dir = ZAP_RAW_DIR / "docker"
    if zap_docker_dir.is_dir():
        zap_docker_docs = parse_generic_markdown_directory(
            zap_docker_dir,
            source_name="OWASP ZAP Docker Guides",
            doc_type="scanner_document",
            doc_id_prefix="zap-docker",
            extra_tags=["zap", "docker"],
        )
        for doc in zap_docker_docs:
            validate_document(doc, validator)
            registry.add(doc)

    # 10. Curated Vulnerability Examples
    if EXAMPLES_DIR.is_dir():
        examples = parse_example_directory(EXAMPLES_DIR)
        for doc in examples:
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
) -> None:
    """Generate dense embeddings and upsert all documents into Qdrant Vector Store."""
    if documents is None:
        from src.retrieval.storage.jsonl_store import read_documents

        if not DOCUMENTS_PATH.is_file():
            build_documents()
        documents = read_documents(DOCUMENTS_PATH)

    client = EmbeddingClient()
    store = QdrantVectorStore(storage_path=qdrant_storage_path, collection_name=collection_name)
    store.init_collection(recreate=True)

    # Embed text for all documents
    passages = [f"{doc.title}\n\n{doc.summary}\n\n{doc.content}" for doc in documents]
    embeddings = client.embed_texts(passages)
    store.upsert_documents(documents, embeddings)
