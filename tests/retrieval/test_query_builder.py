import sqlite3

import pytest

from src.retrieval.exceptions import InvalidSearchQueryError
from src.retrieval.normalization import normalize_query, tokenize_search_query
from src.retrieval.query_builder import build_match_expression, quote_fts_phrase

UNTRUSTED_QUERIES = (
    "SQL Injection OR 1=1",
    "SQL AND Injection",
    "NOT XSS",
    "NEAR XSS",
    'XSS"',
    "XSS*",
    "^XSS",
    "() XSS",
    ": XSS",
    "- XSS",
)


def test_reserved_words_and_special_characters_execute_as_literals() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
    connection.execute("INSERT INTO test_fts(content) VALUES (?)", ("SQL Injection OR 1 AND NOT NEAR XSS",))
    try:
        for query in UNTRUSTED_QUERIES:
            normalized = normalize_query(query)
            expression = build_match_expression(tokenize_search_query(normalized))
            connection.execute(
                "SELECT rowid FROM test_fts WHERE test_fts MATCH ?",
                (expression,),
            ).fetchall()
    finally:
        connection.close()


def test_boolean_keyword_is_quoted_as_a_literal_token() -> None:
    expression = build_match_expression(tokenize_search_query(normalize_query("SQL OR Injection")))
    assert expression == '"SQL" "OR" "Injection"'


def test_embedded_quote_is_escaped() -> None:
    assert quote_fts_phrase('a"b') == '"a""b"'


@pytest.mark.parametrize("query", ["", "   ", '" * ^ : - ( )', "()", ":", "-"])
def test_empty_or_special_only_query_is_rejected(query: str) -> None:
    with pytest.raises(InvalidSearchQueryError, match="searchable terms"):
        build_match_expression(tokenize_search_query(normalize_query(query)))
