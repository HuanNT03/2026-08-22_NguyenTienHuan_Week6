"""Safe construction of SQLite FTS5 MATCH expressions with multi-keyword parsing."""

import re

from src.retrieval.exceptions import InvalidSearchQueryError
from src.retrieval.normalization import normalize_query, tokenize_search_query

_DISJUNCTION_SPLIT = re.compile(r"\s+(?:hoặc|or|hay)\s+|,\s*", flags=re.IGNORECASE)
_CONNECTIVE_WORDS = {
    "và",
    "va",
    "and",
    "với",
    "voi",
    "cùng",
    "cung",
    "trong",
    "của",
    "cua",
    "the",
    "in",
    "for",
    "with",
    "to",
    "of",
}


def quote_fts_phrase(value: str) -> str:
    """Quote one literal FTS5 phrase and escape embedded quote characters."""
    escaped = value.replace('"', '""')
    return f'"{escaped}"'


def build_match_expression(tokens: list[str]) -> str:
    """Join allowlisted tokens as implicit-AND literal FTS phrases."""
    if not tokens:
        raise InvalidSearchQueryError("Search query does not contain searchable terms.")
    return " ".join(quote_fts_phrase(token) for token in tokens)


def build_smart_match_expression(query: str | list[str]) -> str:
    """Build a flexible FTS5 MATCH expression supporting conjunctions (AND/OR) and multi-terms.

    Recognizes natural conjunctions ('hoặc', 'or', commas) as OR-clauses while filtering
    connective words ('và', 'and', 'with') within clauses so multi-keyword searches achieve high recall.
    """
    if isinstance(query, list):
        return build_match_expression(query)

    if not query or not query.strip():
        raise InvalidSearchQueryError("Search query does not contain searchable terms.")

    normalized = normalize_query(query)
    clauses = _DISJUNCTION_SPLIT.split(normalized)

    clause_expressions: list[str] = []
    all_tokens: list[str] = []

    for clause in clauses:
        tokens = tokenize_search_query(clause)
        # Filter noise connective words unless it's a standalone term
        filtered = [t for t in tokens if t.casefold() not in _CONNECTIVE_WORDS]
        if not filtered:
            filtered = tokens
        if not filtered:
            continue

        all_tokens.extend(filtered)
        quoted = [quote_fts_phrase(token) for token in filtered]
        if len(quoted) > 1:
            clause_expressions.append(f"({' '.join(quoted)})")
        else:
            clause_expressions.append(quoted[0])

    if not clause_expressions:
        raise InvalidSearchQueryError("Search query does not contain searchable terms.")

    if len(clause_expressions) > 1:
        return " OR ".join(clause_expressions)

    # For single clause with multiple tokens, join with space (implicit AND in FTS5)
    tokens = tokenize_search_query(normalized)
    filtered = [t for t in tokens if t.casefold() not in _CONNECTIVE_WORDS]
    if not filtered:
        filtered = tokens
    return " ".join(quote_fts_phrase(token) for token in filtered)
