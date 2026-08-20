from pathlib import Path

import pytest

from src.retrieval.exceptions import InvalidSearchQueryError, KnowledgeIndexNotFoundError
from src.retrieval.service import KnowledgeSearchService


@pytest.mark.parametrize("query", ["CWE-79", "cwe79", "cwe 79", "cwe_79"])
def test_cwe_variants_have_same_top_result(canonical_index: Path, query: str) -> None:
    results = KnowledgeSearchService(canonical_index).search(query)
    assert results[0].doc_id == "cwe-79"
    assert results[0].exact_match_rank == 0


@pytest.mark.parametrize("query", ["A01:2025", "A01-2025", "a01 2025", "a1:2025"])
def test_owasp_variants_have_same_top_result(canonical_index: Path, query: str) -> None:
    results = KnowledgeSearchService(canonical_index).search(query)
    assert results[0].doc_id == "owasp-2025-a01"
    assert results[0].exact_match_rank == 0


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("SQL Injection", {"cwe-89", "example-sql-injection-nodejs", "semgrep-vuln-sql-injection"}),
        ("SQLi", {"cwe-89"}),
        ("XSS", {"cwe-79"}),
        ("CWE79", {"cwe-79"}),
        ("Broken Access Control", {"owasp-2025-a01", "owasp-2021-a01", "owasp-2017-a05"}),
        ("Security Misconfiguration", {"owasp-2025-a02", "owasp-2021-a05", "owasp-2017-a06"}),
        ("IDOR", {"cwe-639", "example-idor"}),
        ("XXE", {"cwe-611", "example-xxe", "owasp-2017-a04"}),
    ],
)
def test_required_search_behaviors(canonical_index: Path, query: str, expected: set[str]) -> None:
    results = KnowledgeSearchService(canonical_index).search(query)
    assert results
    assert results[0].doc_id in expected


def test_unknown_query_returns_empty_list(canonical_index: Path) -> None:
    assert KnowledgeSearchService(canonical_index).search("sentineltermthatdoesnotexist") == []


def test_doc_type_filter_is_bound_and_applied(canonical_index: Path) -> None:
    results = KnowledgeSearchService(canonical_index).search("IDOR", doc_type="cwe")
    assert results
    assert all(result.doc_type == "cwe" for result in results)


@pytest.mark.parametrize("top_k", [0, 51, True])
def test_invalid_top_k_is_rejected(canonical_index: Path, top_k: int) -> None:
    with pytest.raises(InvalidSearchQueryError, match="top_k"):
        KnowledgeSearchService(canonical_index).search("XSS", top_k=top_k)


def test_invalid_doc_type_is_rejected(canonical_index: Path) -> None:
    with pytest.raises(InvalidSearchQueryError, match="doc_type"):
        KnowledgeSearchService(canonical_index).search("XSS", doc_type="cwe' OR 1=1")


def test_missing_index_has_clear_error(tmp_path: Path) -> None:
    with pytest.raises(KnowledgeIndexNotFoundError, match="Run the knowledge-base build"):
        KnowledgeSearchService(tmp_path / "missing.db").search("XSS")


def test_search_service_get_document(canonical_index: Path) -> None:
    service = KnowledgeSearchService(canonical_index)
    doc = service.get_document("cwe-89")
    assert doc is not None
    assert doc.doc_id == "cwe-89"
    assert doc.title == "CWE-89: SQL Injection"
    assert len(doc.content) > 0

    assert service.get_document("non-existent-doc-id") is None


def test_search_semantic_and_hybrid_hydrates_parent(canonical_index: Path) -> None:
    service = KnowledgeSearchService(canonical_index)

    # Hybrid Search
    hybrid_results = service.search("SQL Injection", mode="hybrid", top_k=3)
    assert len(hybrid_results) > 0
    assert hybrid_results[0].content != ""
    assert hybrid_results[0].title != ""

    # Semantic Search
    semantic_results = service.search("how to prevent injection attacks", mode="semantic", top_k=3)
    assert len(semantic_results) > 0
    assert semantic_results[0].content != ""
    assert len(semantic_results[0].snippet) > 0
