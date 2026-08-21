"""Public Python search interface for Project Sentinel agents supporting Hybrid, Semantic, and Keyword search."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from src.retrieval.config import DOCUMENT_TYPES, INDEX_PATH, QDRANT_COLLECTION_NAME, QDRANT_STORAGE_DIR
from src.retrieval.embeddings.client import EmbeddingClient
from src.retrieval.exceptions import InvalidSearchQueryError, KnowledgeBaseError
from src.retrieval.hybrid.mmr import maximal_marginal_relevance
from src.retrieval.hybrid.rrf import reciprocal_rank_fusion
from src.retrieval.models import KnowledgeDocument
from src.retrieval.normalization import normalize_query
from src.retrieval.query_builder import build_smart_match_expression
from src.retrieval.repository import KnowledgeRepository
from src.retrieval.vector.qdrant_store import QdrantVectorStore


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
    score: float
    exact_match_rank: int = 3
    matched_section: str = ""
    content: str = ""

    @property
    def bm25_score(self) -> float:
        """Alias score for backwards compatibility with BM25 tests."""
        return self.score


class KnowledgeSearchService:
    """Validate user input and execute Two-Stage Hybrid, Semantic, or Keyword retrieval."""

    def __init__(
        self,
        index_path: Path = INDEX_PATH,
        qdrant_path: Path = QDRANT_STORAGE_DIR,
        collection_name: str = QDRANT_COLLECTION_NAME,
    ) -> None:
        """Initialize search service with SQLite repository and Qdrant vector store.

        Args:
            index_path: Path to the SQLite FTS5 index database file.
            qdrant_path: Path to the directory storing Qdrant vector collection.
            collection_name: Identifier of the collection in Qdrant.
        """
        self.index_path = index_path
        self.qdrant_path = qdrant_path
        self.collection_name = collection_name
        self.repository = KnowledgeRepository(index_path)
        self._vector_store: QdrantVectorStore | None = None
        self.embedding_client = EmbeddingClient()

    @property
    def vector_store(self) -> QdrantVectorStore:
        """Lazy-loaded QdrantVectorStore instance."""
        if self._vector_store is None:
            self._vector_store = QdrantVectorStore(
                storage_path=self.qdrant_path,
                collection_name=self.collection_name,
            )
        return self._vector_store

    def get_document(self, doc_id: str) -> KnowledgeDocument | None:
        """Retrieve a full canonical KnowledgeDocument by its unique doc_id.

        Args:
            doc_id: Canonical document identifier (e.g. 'cwe-89', 'owasp-2025-a01').

        Returns:
            KnowledgeDocument object if found, or None if no document matches the ID.
        """
        records = self.repository.get_documents_by_ids([doc_id])
        if not records:
            return None
        data = records[0]
        from src.retrieval.models import KnowledgeIdentifiers, KnowledgeSource

        return KnowledgeDocument(
            schema_version="1.0.0",
            doc_id=data["doc_id"],
            doc_type=data["doc_type"],
            title=data["title"],
            aliases=data["aliases"],
            summary=data["summary"],
            content=data["content"],
            identifiers=KnowledgeIdentifiers(**data["identifiers"]),
            tags=data["tags"],
            source=KnowledgeSource(**data["source"]),
        )

    def search(
        self,
        query: str,
        top_k: int = 5,
        doc_type: str | None = None,
        mode: Literal["hybrid", "keyword", "semantic"] = "keyword",
        lambda_mult: float = 0.7,
    ) -> list[SearchResult]:
        """Search canonical knowledge using Keyword, Semantic, or Two-Stage Hybrid (RRF + MMR) search.

        Args:
            query: Non-empty search query string from user or security agent.
            top_k: Maximum number of ranked results to return (1 to 50).
            doc_type: Optional document type filter (e.g. 'owasp_category', 'cwe').
            mode: Search retrieval mode ('hybrid', 'keyword', or 'semantic').
            lambda_mult: Diversity balancing parameter for MMR reranking (0.0 to 1.0).

        Returns:
            List of SearchResult objects containing ranked parent documents and matched snippets.

        Raises:
            InvalidSearchQueryError: If query, top_k, doc_type, or mode is invalid.
        """
        if not isinstance(query, str) or not query.strip():
            raise InvalidSearchQueryError("Search query must be a non-empty string.")
        if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= 50:
            raise InvalidSearchQueryError("top_k must be between 1 and 50.")
        if doc_type is not None and doc_type not in DOCUMENT_TYPES:
            raise InvalidSearchQueryError(
                f"Unsupported doc_type {doc_type!r}; expected one of: {', '.join(DOCUMENT_TYPES)}."
            )
        if mode not in ("hybrid", "keyword", "semantic"):
            raise InvalidSearchQueryError(f"Unsupported mode {mode!r}; expected 'hybrid', 'keyword', or 'semantic'.")

        if mode == "keyword":
            return self.search_keyword(query=query, top_k=top_k, doc_type=doc_type)
        if mode == "semantic":
            return self.search_semantic(query=query, top_k=top_k, doc_type=doc_type)
        return self.search_hybrid(query=query, top_k=top_k, doc_type=doc_type, lambda_mult=lambda_mult)

    def search_keyword(
        self,
        query: str,
        top_k: int = 5,
        doc_type: str | None = None,
    ) -> list[SearchResult]:
        """Search using SQLite FTS5 with smart multi-keyword parser and BM25 ranking.

        Args:
            query: Search query text.
            top_k: Maximum number of ranked results.
            doc_type: Optional document type filter.

        Returns:
            List of SearchResult objects ranked by exact matches and BM25 score.
        """
        normalized = normalize_query(query)
        expression = build_smart_match_expression(normalized)
        rows = self.repository.search(
            normalized_query=normalized,
            match_expression=expression,
            top_k=top_k,
            doc_type=doc_type,
        )
        doc_ids = [row["doc_id"] for row in rows]
        hydrated = {d["doc_id"]: d for d in self.repository.get_documents_by_ids(doc_ids)}

        return [
            SearchResult(
                doc_id=row["doc_id"],
                doc_type=row["doc_type"],
                title=row["title"],
                snippet=row["snippet"],
                summary=row["summary"],
                aliases=row["aliases"],
                identifiers=row["identifiers"],
                tags=row["tags"],
                score=float(row["bm25_score"]),
                exact_match_rank=int(row["exact_match_rank"]),
                matched_section="",
                content=hydrated.get(row["doc_id"], {}).get("content", ""),
            )
            for row in rows
        ]

    def search_semantic(
        self,
        query: str,
        top_k: int = 5,
        doc_type: str | None = None,
    ) -> list[SearchResult]:
        """Search using section-aware child chunks in Qdrant and hydrate parent documents.

        Args:
            query: Natural language search query or finding description.
            top_k: Maximum number of unique parent documents to return.
            doc_type: Optional document type filter.

        Returns:
            List of SearchResult objects with child section matched snippets and full parent content.
        """
        if self.embedding_client.provider == "mock" and self.embedding_client.dimension != self.vector_store.dimension:
            self.embedding_client.dimension = self.vector_store.dimension
        query_vector = self.embedding_client.embed_query(query)
        dense_results = self.vector_store.search_parents(
            query_vector=query_vector,
            top_k=top_k,
            doc_type=doc_type,
        )
        doc_ids = [r.doc_id for r in dense_results]
        hydrated_docs = {d["doc_id"]: d for d in self.repository.get_documents_by_ids(doc_ids)}

        results: list[SearchResult] = []
        for r in dense_results:
            doc_data = hydrated_docs.get(r.doc_id)
            if doc_data:
                snippet = r.matched_snippet if r.matched_snippet else doc_data["snippet"]
                results.append(
                    SearchResult(
                        doc_id=doc_data["doc_id"],
                        doc_type=doc_data["doc_type"],
                        title=doc_data["title"],
                        snippet=snippet,
                        summary=doc_data["summary"],
                        aliases=doc_data["aliases"],
                        identifiers=doc_data["identifiers"],
                        tags=doc_data["tags"],
                        score=r.score,
                        matched_section=r.matched_section,
                        content=doc_data["content"],
                    )
                )
        return results

    def search_hybrid(
        self,
        query: str,
        top_k: int = 5,
        doc_type: str | None = None,
        lambda_mult: float = 0.7,
    ) -> list[SearchResult]:
        """Two-Stage Hybrid Search: Stage 1 RRF Fusion + Stage 2 Pure MMR Diversity Reranking.

        Args:
            query: Search query text.
            top_k: Maximum number of diverse parent documents to return.
            doc_type: Optional document type filter.
            lambda_mult: Diversity factor for MMR reranking (0.7 balances relevance and diversity).

        Returns:
            List of diverse, high-relevance SearchResult objects with full parent hydration.
        """
        candidate_k = max(20, top_k * 4)

        # 1. Sparse Candidate Retrieval (FTS5 BM25)
        try:
            sparse_results = self.search_keyword(query=query, top_k=candidate_k, doc_type=doc_type)
        except (KnowledgeBaseError, RuntimeError, ValueError, OSError):
            sparse_results = []
        sparse_doc_ids = [r.doc_id for r in sparse_results]

        # 2. Dense Candidate Retrieval (Qdrant Cosine with Parent Aggregation)
        if self.embedding_client.provider == "mock" and self.embedding_client.dimension != self.vector_store.dimension:
            self.embedding_client.dimension = self.vector_store.dimension
        query_vector = self.embedding_client.embed_query(query)
        try:
            dense_results = self.vector_store.search_parents(
                query_vector=query_vector,
                top_k=candidate_k,
                doc_type=doc_type,
            )
        except (KnowledgeBaseError, RuntimeError, ValueError, OSError):
            dense_results = []
        dense_doc_ids = [r.doc_id for r in dense_results]
        candidate_vectors = {r.doc_id: r.vector for r in dense_results}
        dense_snippets = {r.doc_id: (r.matched_snippet, r.matched_section) for r in dense_results if r.matched_snippet}

        # 3. Stage 1: Reciprocal Rank Fusion (RRF)
        rrf_ranked = reciprocal_rank_fusion(sparse_doc_ids, dense_doc_ids, k=60)
        if not rrf_ranked:
            return []

        rrf_candidate_ids = [doc_id for doc_id, _ in rrf_ranked[:candidate_k]]
        rrf_scores = dict(rrf_ranked)

        # 4. Stage 2: Pure MMR Diversity Reranking
        selected_ids = maximal_marginal_relevance(
            query_vector=query_vector,
            candidate_doc_ids=rrf_candidate_ids,
            candidate_vectors=candidate_vectors,
            candidate_relevance_scores=rrf_scores,
            top_k=top_k,
            lambda_mult=lambda_mult,
        )

        # 5. Hydrate final documents
        hydrated_docs = {d["doc_id"]: d for d in self.repository.get_documents_by_ids(selected_ids)}
        results: list[SearchResult] = []
        for doc_id in selected_ids:
            doc_data = hydrated_docs.get(doc_id)
            if doc_data:
                matched_snippet, matched_section = dense_snippets.get(doc_id, (doc_data["snippet"], ""))
                results.append(
                    SearchResult(
                        doc_id=doc_data["doc_id"],
                        doc_type=doc_data["doc_type"],
                        title=doc_data["title"],
                        snippet=matched_snippet or doc_data["snippet"],
                        summary=doc_data["summary"],
                        aliases=doc_data["aliases"],
                        identifiers=doc_data["identifiers"],
                        tags=doc_data["tags"],
                        score=rrf_scores.get(doc_id, 0.0),
                        matched_section=matched_section,
                        content=doc_data["content"],
                    )
                )

        return results
