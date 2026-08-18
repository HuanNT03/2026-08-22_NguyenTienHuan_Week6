"""Public Python search interface for Project Sentinel agents supporting Hybrid, Semantic, and Keyword search."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from src.retrieval.config import DOCUMENT_TYPES, INDEX_PATH, QDRANT_COLLECTION_NAME, QDRANT_STORAGE_DIR
from src.retrieval.embeddings.client import EmbeddingClient
from src.retrieval.exceptions import InvalidSearchQueryError, KnowledgeBaseError
from src.retrieval.hybrid.mmr import maximal_marginal_relevance
from src.retrieval.hybrid.rrf import reciprocal_rank_fusion
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
        self.repository = KnowledgeRepository(index_path)
        self.vector_store = QdrantVectorStore(storage_path=qdrant_path, collection_name=collection_name)
        self.embedding_client = EmbeddingClient()

    def search(
        self,
        query: str,
        top_k: int = 5,
        doc_type: str | None = None,
        mode: Literal["hybrid", "keyword", "semantic"] = "keyword",
        lambda_mult: float = 0.7,
    ) -> list[SearchResult]:
        """Search canonical knowledge using Keyword, Semantic, or Two-Stage Hybrid (RRF + MMR) search."""
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
        """Search using SQLite FTS5 with smart multi-keyword parser and BM25 ranking."""
        normalized = normalize_query(query)
        expression = build_smart_match_expression(normalized)
        rows = self.repository.search(
            normalized_query=normalized,
            match_expression=expression,
            top_k=top_k,
            doc_type=doc_type,
        )
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
            )
            for row in rows
        ]

    def search_semantic(
        self,
        query: str,
        top_k: int = 5,
        doc_type: str | None = None,
    ) -> list[SearchResult]:
        """Search using dense vectors and Cosine distance in Qdrant Vector Store."""
        query_vector = self.embedding_client.embed_query(query)
        dense_results = self.vector_store.search(
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
                results.append(
                    SearchResult(
                        doc_id=doc_data["doc_id"],
                        doc_type=doc_data["doc_type"],
                        title=doc_data["title"],
                        snippet=doc_data["snippet"],
                        summary=doc_data["summary"],
                        aliases=doc_data["aliases"],
                        identifiers=doc_data["identifiers"],
                        tags=doc_data["tags"],
                        score=r.score,
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
        """Two-Stage Hybrid Search: Stage 1 RRF Fusion + Stage 2 Pure MMR Diversity Reranking."""
        candidate_k = max(20, top_k * 4)

        # 1. Sparse Candidate Retrieval (FTS5 BM25)
        sparse_results = []
        try:
            sparse_results = self.search_keyword(query=query, top_k=candidate_k, doc_type=doc_type)
        except (KnowledgeBaseError, RuntimeError, ValueError, OSError):
            sparse_results = []
        sparse_doc_ids = [r.doc_id for r in sparse_results]

        # 2. Dense Candidate Retrieval (Qdrant Cosine)
        query_vector = self.embedding_client.embed_query(query)
        dense_results = []
        try:
            dense_results = self.vector_store.search(query_vector=query_vector, top_k=candidate_k, doc_type=doc_type)
        except (KnowledgeBaseError, RuntimeError, ValueError, OSError):
            dense_results = []
        dense_doc_ids = [r.doc_id for r in dense_results]
        candidate_vectors = {r.doc_id: r.vector for r in dense_results}

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
                results.append(
                    SearchResult(
                        doc_id=doc_data["doc_id"],
                        doc_type=doc_data["doc_type"],
                        title=doc_data["title"],
                        snippet=doc_data["snippet"],
                        summary=doc_data["summary"],
                        aliases=doc_data["aliases"],
                        identifiers=doc_data["identifiers"],
                        tags=doc_data["tags"],
                        score=rrf_scores.get(doc_id, 0.0),
                    )
                )

        return results
