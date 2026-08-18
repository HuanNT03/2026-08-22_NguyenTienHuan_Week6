"""Unit tests for Smart Multi-Keyword query builder and normalization."""

import sqlite3

import pytest

from src.retrieval.exceptions import InvalidSearchQueryError
from src.retrieval.query_builder import build_smart_match_expression


def test_smart_query_builder_handles_single_keyword() -> None:
    expr = build_smart_match_expression("SQL Injection")
    assert expr.casefold() == '"sql" "injection"'


def test_smart_query_builder_handles_vietnamese_and_english_conjunctions() -> None:
    # "cwe 89 và owasp a05:2025"
    expr1 = build_smart_match_expression("cwe 89 và owasp a05:2025")
    assert '"CWE-89"' in expr1
    assert '"A05:2025"' in expr1

    # Disjunction with "hoặc" / "or" / comma
    expr2 = build_smart_match_expression("cwe 89 hoặc owasp a05:2025")
    assert " OR " in expr2
    assert '("CWE-89")' in expr2 or '"CWE-89"' in expr2
    assert '("A05:2025")' in expr2 or '"A05:2025"' in expr2

    # Comma separation
    expr3 = build_smart_match_expression("XSS, CSRF, IDOR")
    assert " OR " in expr3


def test_smart_query_builder_executes_safely_in_sqlite_fts5() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
    connection.execute("INSERT INTO test_fts(content) VALUES (?)", ("CWE-89 SQL Injection in Node.js",))
    connection.execute("INSERT INTO test_fts(content) VALUES (?)", ("A05:2025 Injection category overview",))

    try:
        # Multi-keyword OR query matches both documents
        expr = build_smart_match_expression("cwe 89 hoặc owasp a05:2025")
        rows = connection.execute("SELECT content FROM test_fts WHERE test_fts MATCH ?", (expr,)).fetchall()
        assert len(rows) == 2

        # Complex query with conjunction
        expr2 = build_smart_match_expression("cwe 89 và owasp a05:2025")
        # Should be valid FTS syntax
        rows2 = connection.execute("SELECT content FROM test_fts WHERE test_fts MATCH ?", (expr2,)).fetchall()
        assert isinstance(rows2, list)
    finally:
        connection.close()


def test_empty_query_raises_invalid_search_query_error() -> None:
    with pytest.raises(InvalidSearchQueryError):
        build_smart_match_expression("   ")
