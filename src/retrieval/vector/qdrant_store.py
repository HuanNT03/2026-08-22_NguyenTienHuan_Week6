"""Qdrant Embedded Vector Store adapter for Project Sentinel."""

import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.http import models as rest_models

from src.retrieval.chunking.markdown_chunker import DocumentChunk
from src.retrieval.config import QDRANT_COLLECTION_NAME, QDRANT_STORAGE_DIR
from src.retrieval.models import KnowledgeDocument


@dataclass(frozen=True)
class VectorSearchResult:
    """A search result retrieved from the dense vector index."""

    doc_id: str
    score: float
    vector: list[float]
    payload: dict[str, Any]
    chunk_id: str = ""
    matched_section: str = ""
    matched_snippet: str = ""


class QdrantVectorStore:
    """Manages an embedded Qdrant vector database instance for dense similarity search."""

    def __init__(
        self,
        storage_path: Path | None = None,
        collection_name: str = QDRANT_COLLECTION_NAME,
        dimension: int = 1536,
    ) -> None:
        """Initialize the Qdrant embedded vector store.

        Args:
            storage_path: Optional directory path where Qdrant storage files will reside.
            collection_name: Name of the vector collection to create and query.
            dimension: Default vector dimension. Overridden by EMBEDDING_DIMENSION env var if present.
        """
        self.storage_path = storage_path or QDRANT_STORAGE_DIR
        self.collection_name = collection_name
        self.dimension = int(os.getenv("EMBEDDING_DIMENSION", str(dimension)))
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.client = QdrantClient(path=str(self.storage_path))

    def init_collection(self, recreate: bool = False) -> None:
        """Create or recreate the vector collection with Cosine distance.

        Args:
            recreate: If True, deletes existing collection and creates a clean empty collection.
        """
        collections = self.client.get_collections().collections
        exists = any(col.name == self.collection_name for col in collections)

        if exists and recreate:
            self.client.delete_collection(collection_name=self.collection_name)
            exists = False

        if not exists:
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=rest_models.VectorParams(
                    size=self.dimension,
                    distance=rest_models.Distance.COSINE,
                ),
            )

    def upsert_chunks(
        self,
        chunks: list[DocumentChunk],
        embeddings: list[list[float]],
    ) -> None:
        """Upsert section-aware child chunks with their dense embeddings and payload metadata.

        Args:
            chunks: List of DocumentChunk instances to upsert into the vector store.
            embeddings: List of float vectors matching the exact count and order of chunks.

        Raises:
            ValueError: If the lengths of chunks and embeddings do not match.
        """
        if len(chunks) != len(embeddings):
            raise ValueError(f"Mismatch: {len(chunks)} chunks and {len(embeddings)} embeddings")

        if not chunks:
            return

        self.init_collection(recreate=False)

        points: list[rest_models.PointStruct] = []
        for chunk, vector in zip(chunks, embeddings, strict=True):
            point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, chunk.chunk_id))
            payload = {
                "chunk_id": chunk.chunk_id,
                "parent_doc_id": chunk.parent_doc_id,
                "doc_id": chunk.parent_doc_id,
                "doc_type": chunk.doc_type,
                "title": chunk.parent_title,
                "section_title": chunk.section_title,
                "chunk_text": chunk.content,
            }
            points.append(
                rest_models.PointStruct(
                    id=point_id,
                    vector=vector,
                    payload=payload,
                )
            )

        batch_size = 100
        for i in range(0, len(points), batch_size):
            batch = points[i : i + batch_size]
            self.client.upsert(
                collection_name=self.collection_name,
                points=batch,
            )

    def upsert_documents(
        self,
        documents: list[KnowledgeDocument],
        embeddings: list[list[float]],
    ) -> None:
        """Upsert whole documents for backward compatibility with single-vector interfaces.

        Args:
            documents: List of parent KnowledgeDocument objects.
            embeddings: Corresponding list of dense embedding vectors.
        """
        if len(documents) != len(embeddings):
            raise ValueError(f"Mismatch: {len(documents)} documents and {len(embeddings)} embeddings")

        chunks = [
            DocumentChunk(
                chunk_id=f"{doc.doc_id}#main",
                parent_doc_id=doc.doc_id,
                parent_title=doc.title,
                section_title="Overview",
                content=f"# {doc.title}\n\n{doc.summary}\n\n{doc.content}",
                doc_type=doc.doc_type,
            )
            for doc in documents
        ]
        self.upsert_chunks(chunks, embeddings)

    def search_parents(
        self,
        query_vector: list[float],
        top_k: int = 20,
        doc_type: str | None = None,
    ) -> list[VectorSearchResult]:
        """Search child chunks and aggregate by parent_doc_id using maximum cosine similarity.

        Queries a wider window of child vectors, deduplicates results by their parent document,
        and assigns the highest-scoring section's snippet and score to each parent document.

        Args:
            query_vector: Dense embedding vector representing the user query.
            top_k: Number of unique parent documents to return (clamped between 1 and 50).
            doc_type: Optional filter to restrict results to a specific document type.

        Returns:
            List of VectorSearchResult objects deduplicated by parent_doc_id and sorted by score descending.
        """
        query_filter = None
        if doc_type:
            query_filter = rest_models.Filter(
                must=[
                    rest_models.FieldCondition(
                        key="doc_type",
                        match=rest_models.MatchValue(value=doc_type),
                    )
                ]
            )

        # Retrieve a broader candidate pool of child chunks
        candidate_limit = min(max(top_k * 5, 20), 200)
        results = self.client.query_points(
            collection_name=self.collection_name,
            query=query_vector,
            query_filter=query_filter,
            limit=candidate_limit,
            with_payload=True,
            with_vectors=True,
        ).points

        parent_best: dict[str, VectorSearchResult] = {}
        for point in results:
            payload = point.payload or {}
            parent_id = str(payload.get("parent_doc_id") or payload.get("doc_id") or point.id)
            score = float(point.score if point.score is not None else 0.0)
            vector = point.vector if isinstance(point.vector, list) else []

            if parent_id not in parent_best or score > parent_best[parent_id].score:
                parent_best[parent_id] = VectorSearchResult(
                    doc_id=parent_id,
                    score=score,
                    vector=list(vector) if vector is not None else [],
                    payload=payload,
                    chunk_id=str(payload.get("chunk_id", "")),
                    matched_section=str(payload.get("section_title", "")),
                    matched_snippet=str(payload.get("chunk_text", "")),
                )

        sorted_parents = sorted(parent_best.values(), key=lambda r: r.score, reverse=True)[:top_k]
        return sorted_parents

    def search(
        self,
        query_vector: list[float],
        top_k: int = 20,
        doc_type: str | None = None,
    ) -> list[VectorSearchResult]:
        """Convenience alias for search_parents providing aggregated multi-vector retrieval.

        Args:
            query_vector: Dense query vector.
            top_k: Maximum number of parent documents to return.
            doc_type: Optional document type filter.

        Returns:
            List of parent VectorSearchResult items sorted by highest similarity score.
        """
        return self.search_parents(query_vector=query_vector, top_k=top_k, doc_type=doc_type)
