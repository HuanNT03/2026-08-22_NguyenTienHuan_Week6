"""Tests for knowledge base inventory and curated example tracking."""

from src.retrieval.build import collect_documents
from src.retrieval.config import EXAMPLES_DIR, PROJECT_ROOT
from src.retrieval.parsers.example_parser import parse_example_directory

EXAMPLE_IDS = {
    "example-sql-injection-nodejs",
    "example-reflected-xss-express",
    "example-stored-xss",
    "example-dom-based-xss",
    "example-idor",
    "example-missing-function-level-authorization",
    "example-authentication-bypass",
    "example-csrf",
    "example-path-traversal",
    "example-os-command-injection",
    "example-ssrf",
    "example-open-redirect",
    "example-unrestricted-file-upload",
    "example-xxe",
    "example-cors-misconfiguration",
    "example-prototype-pollution",
    "example-weak-jwt-signing",
    "example-missing-rate-limiting",
    "example-sensitive-data-logging",
    "example-verbose-error-leakage",
}


def test_documented_inventory_matches_parsed_examples() -> None:
    examples = parse_example_directory(EXAMPLES_DIR)
    assert {document.doc_id for document in examples} == EXAMPLE_IDS


def test_collection_result_ingests_all_sources() -> None:
    collection = collect_documents()
    assert len(collection.documents) >= 1800
    doc_types = {doc.doc_type for doc in collection.documents}
    assert "cwe" in doc_types
    assert "owasp_category" in doc_types
    assert "asvs_requirement" in doc_types
    assert "cheatsheet" in doc_types
    assert "scanner_rule" in doc_types
    assert "scanner_document" in doc_types
    assert "vulnerability_example" in doc_types


def test_every_curated_example_is_listed_in_review_document() -> None:
    review = (
        PROJECT_ROOT / "docs" / "reports" / "week2" / "week-2-knowledgebase.md"
    ).read_text(encoding="utf-8")
    examples = parse_example_directory(EXAMPLES_DIR)
    for document in examples:
        assert document.doc_id in review
