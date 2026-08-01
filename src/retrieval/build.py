"""Orchestration for validation and deterministic canonical document builds."""

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from src.retrieval.config import (
    CWE_RAW_PATHS,
    DOCUMENTS_PATH,
    EXAMPLES_DIR,
    MANIFEST_PATH,
    OWASP_RAW_DIR,
    SCHEMA_PATH,
    SCHEMA_VERSION,
    SEMGREP_RAW_DIR,
    ZAP_RAW_DIR,
)
from src.retrieval.exceptions import DuplicateDocumentIdError, SourceValidationError
from src.retrieval.models import KnowledgeDocument
from src.retrieval.parsers.cwe_parser import CweParseResult, parse_cwe_views
from src.retrieval.parsers.example_parser import parse_example_directory
from src.retrieval.parsers.owasp_parser import parse_owasp_directory
from src.retrieval.parsers.scanner_parser import parse_scanner_directories
from src.retrieval.storage.jsonl_store import atomic_write_bytes, serialize_documents, sha256_bytes
from src.retrieval.validation import build_knowledge_validator, load_knowledge_schema, validate_document

EXPECTED_COUNTS = {
    "cwe": 409,
    "owasp_category": 10,
    "scanner_document": 4,
    "scanner_rule": 4,
    "vulnerability_example": 15,
}


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


def _validate_counts(documents: list[KnowledgeDocument], cwe_result: CweParseResult) -> None:
    counts = Counter(document.doc_type for document in documents)
    if dict(sorted(counts.items())) != dict(sorted(EXPECTED_COUNTS.items())):
        raise SourceValidationError(f"Unexpected document counts: expected {EXPECTED_COUNTS}, found {dict(counts)}")
    if cwe_result.input_counts != {"699": 399, "1435": 25} or cwe_result.coalesced_records != 15:
        raise SourceValidationError(
            "Unexpected CWE ingestion counts: expected 399 View 699, 25 View 1435, and 15 coalesced; "
            f"found {cwe_result.input_counts} and {cwe_result.coalesced_records} coalesced"
        )


def collect_documents() -> CollectionResult:
    """Parse, validate, and register every configured knowledge source."""
    owasp_documents, warnings = parse_owasp_directory(OWASP_RAW_DIR)
    cwe_result = parse_cwe_views(CWE_RAW_PATHS)
    example_documents = parse_example_directory(EXAMPLES_DIR)
    scanner_documents = parse_scanner_directories((SEMGREP_RAW_DIR, ZAP_RAW_DIR))
    registry = DocumentRegistry()
    validator = build_knowledge_validator(load_knowledge_schema(SCHEMA_PATH))
    for document in [*owasp_documents, *cwe_result.documents, *example_documents, *scanner_documents]:
        validate_document(document, validator)
        registry.add(document)
    documents = registry.documents()
    _validate_counts(documents, cwe_result)
    return CollectionResult(
        documents=documents,
        warnings=warnings,
        input_records={
            "cwe_699_records": cwe_result.input_counts["699"],
            "cwe_1435_records": cwe_result.input_counts["1435"],
            "cwe_coalesced_records": cwe_result.coalesced_records,
            "cwe_documents": len(cwe_result.documents),
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
