import pytest

from src.retrieval.normalization import normalize_query, tokenize_search_query


@pytest.mark.parametrize("query", ["CWE-89", "cwe89", "cwe 89", "cwe_89"])
def test_cwe_variants_normalize_to_canonical_identifier(query: str) -> None:
    assert normalize_query(query) == "CWE-89"


@pytest.mark.parametrize("query", ["A01:2025", "A01-2025", "a01 2025", "a1:2025"])
def test_owasp_variants_normalize_to_canonical_identifier(query: str) -> None:
    assert normalize_query(query) == "A01:2025"


def test_nfkc_and_whitespace_normalization_preserves_normal_words() -> None:
    assert normalize_query("  SQL\t Injection  ") == "SQL Injection"
    assert normalize_query("ＳＱＬ Injection") == "SQL Injection"


def test_identifier_tokens_are_kept_whole_before_fts_quoting() -> None:
    assert tokenize_search_query("CWE-89 A01:2025 SQL Injection") == [
        "CWE-89",
        "A01:2025",
        "SQL",
        "Injection",
    ]
