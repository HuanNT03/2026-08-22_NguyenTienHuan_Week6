"""Tests for deterministic canonical document build pipeline."""

import json
from pathlib import Path

import pytest

from src.retrieval.build import DocumentRegistry, build_documents, collect_documents
from src.retrieval.exceptions import DuplicateDocumentIdError
from src.retrieval.models import KnowledgeDocument
from src.retrieval.storage.jsonl_store import read_documents, sha256_bytes


def _document(raw_path: str) -> KnowledgeDocument:
    return KnowledgeDocument.model_validate(
        {
            "doc_id": "test-document",
            "doc_type": "scanner_document",
            "title": "Test document",
            "aliases": [],
            "summary": "Summary",
            "content": "Content",
            "identifiers": {"cwe": [], "owasp": [], "semgrep": [], "zap": []},
            "tags": [],
            "source": {"name": "Fixture", "raw_path": raw_path},
        }
    )


def test_collection_has_expected_counts_and_cwe_inputs() -> None:
    collection = collect_documents()
    assert len(collection.documents) >= 1800
    assert collection.input_records["cwe_documents"] == 409
    assert [document.doc_id for document in collection.documents] == sorted(
        document.doc_id for document in collection.documents
    )


def test_registry_duplicate_reports_both_sources() -> None:
    registry = DocumentRegistry()
    registry.add(_document("first.md"))
    with pytest.raises(DuplicateDocumentIdError, match=r"Duplicate ID test-document.*first\.md.*second\.md"):
        registry.add(_document("second.md"))


def test_build_is_byte_deterministic_and_manifest_matches(tmp_path: Path) -> None:
    documents_path = tmp_path / "documents.jsonl"
    manifest_path = tmp_path / "manifest.json"
    first = build_documents(documents_path, manifest_path)
    first_documents = documents_path.read_bytes()
    first_manifest = manifest_path.read_bytes()
    second = build_documents(documents_path, manifest_path)
    assert documents_path.read_bytes() == first_documents
    assert manifest_path.read_bytes() == first_manifest
    assert first.documents_sha256 == second.documents_sha256 == sha256_bytes(first_documents)
    manifest = json.loads(first_manifest)
    assert manifest["document_count"] == len(collection_docs := read_documents(documents_path))
    assert manifest["documents_sha256"] == sha256_bytes(first_documents)
    assert len(collection_docs) >= 1800


def test_documents_do_not_copy_raw_content_field(tmp_path: Path) -> None:
    documents_path = tmp_path / "documents.jsonl"
    manifest_path = tmp_path / "manifest.json"
    build_documents(documents_path, manifest_path)
    for line in documents_path.read_text(encoding="utf-8").splitlines():
        assert "raw_content" not in json.loads(line)
