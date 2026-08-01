"""Safe construction of SQLite FTS5 MATCH expressions."""

from src.retrieval.exceptions import InvalidSearchQueryError


def quote_fts_phrase(value: str) -> str:
    """Quote one literal FTS5 phrase and escape embedded quote characters."""
    escaped = value.replace('"', '""')
    return f'"{escaped}"'


def build_match_expression(tokens: list[str]) -> str:
    """Join allowlisted tokens as implicit-AND literal FTS phrases."""
    if not tokens:
        raise InvalidSearchQueryError("Search query does not contain searchable terms.")
    return " ".join(quote_fts_phrase(token) for token in tokens)
