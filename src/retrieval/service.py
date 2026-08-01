"""Public Python search interface for Project Sentinel agents."""

from dataclasses import dataclass
from pathlib import Path

from src.retrieval.config import DOCUMENT_TYPES, INDEX_PATH
from src.retrieval.exceptions import InvalidSearchQueryError
from src.retrieval.normalization import normalize_query, tokenize_search_query
from src.retrieval.query_builder import build_match_expression
from src.retrieval.repository import KnowledgeRepository


@dataclass(frozen=True)
class SearchResult:
    """One ranked knowledge search result."""

    doc_id: str
    doc_type: str
    title: str
    snippet: str
    summary: str
    aliases: list[str]
    identifiers: dict[str, list[str]]
    tags: list[str]
    bm25_score: float
    exact_match_rank: int


class KnowledgeSearchService:
    """Validate user input and execute safe ranked keyword retrieval."""

    def __init__(self, index_path: Path = INDEX_PATH) -> None:
        self.repository = KnowledgeRepository(index_path)

    def search(
        self,
        query: str,
        top_k: int = 5,
        doc_type: str | None = None,
    ) -> list[SearchResult]:
        """Search canonical knowledge by exact tiers followed by weighted BM25."""
        if not isinstance(query, str):
            raise InvalidSearchQueryError("Search query must be a string.")
        if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= 50:
            raise InvalidSearchQueryError("top_k must be between 1 and 50.")
        if doc_type is not None and doc_type not in DOCUMENT_TYPES:
            raise InvalidSearchQueryError(
                f"Unsupported doc_type {doc_type!r}; expected one of: {', '.join(DOCUMENT_TYPES)}."
            )
        normalized = normalize_query(query)
        expression = build_match_expression(tokenize_search_query(normalized))
        rows = self.repository.search(
            normalized_query=normalized,
            match_expression=expression,
            top_k=top_k,
            doc_type=doc_type,
        )
        return [SearchResult(**row) for row in rows]
