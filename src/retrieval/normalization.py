"""User-query normalization that remains separate from FTS syntax building."""

import re
import unicodedata

_CWE_PATTERN = re.compile(r"\bcwe[\s_-]?(\d+)\b", flags=re.IGNORECASE)
_OWASP_PATTERN = re.compile(r"\ba0?(\d{1,2})[\s:_-]+(\d{4})\b", flags=re.IGNORECASE)
_WHITESPACE = re.compile(r"\s+")
_SEARCH_TOKEN_PATTERN = re.compile(
    r"""
    CWE-\d+
    |
    A\d{2}:\d{4}
    |
    [A-Za-z0-9]+
    """,
    flags=re.VERBOSE | re.IGNORECASE,
)


def normalize_query(query: str) -> str:
    """Apply NFKC, whitespace, CWE, and OWASP identifier normalization."""
    normalized = unicodedata.normalize("NFKC", query)
    normalized = _WHITESPACE.sub(" ", normalized).strip()
    normalized = _CWE_PATTERN.sub(lambda match: f"CWE-{int(match.group(1))}", normalized)
    normalized = _OWASP_PATTERN.sub(
        lambda match: f"A{int(match.group(1)):02d}:{match.group(2)}",
        normalized,
    )
    return normalized


def tokenize_search_query(normalized_query: str) -> list[str]:
    """Extract only identifier or alphanumeric tokens accepted by the FTS builder."""
    return _SEARCH_TOKEN_PATTERN.findall(normalized_query)
