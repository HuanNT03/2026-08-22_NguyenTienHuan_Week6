"""Qdrant Embedded Vector Store adapter for Project Sentinel."""

import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.http import models as rest_models

from src.retrieval.config import QDRANT_COLLECTION_NAME, QDRANT_STORAGE_DIR
from src.retrieval.models import KnowledgeDocument


@dataclass(frozen=True)
class VectorSearchResult:
    """A search result retrieved from the dense vector index."""

    doc_id: str
    score: float
    vector: list[float]
    payload: dict[str, Any]


class QdrantVectorStore:
    """Manages an embedded Qdrant vector database instance for dense similarity search."""

    def __init__(
        self,
        storage_path: Path | None = None,
        collection_name: str = QDRANT_COLLECTION_NAME,
        dimension: int = 1536,
    ) -> None:
        self.storage_path = storage_path or QDRANT_STORAGE_DIR
        self.collection_name = collection_name
        self.dimension = int(os.getenv("EMBEDDING_DIMENSION", str(dimension)))
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.client = QdrantClient(path=str(self.storage_path))

    def init_collection(self, recreate: bool = False) -> None:
        """Create or recreate the vector collection with Cosine distance."""
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

    def upsert_documents(
        self,
        documents: list[KnowledgeDocument],
        embeddings: list[list[float]],
    ) -> None:
        """Upsert documents with their corresponding embeddings and metadata payloads."""
        if len(documents) != len(embeddings):
            raise ValueError(f"Mismatch: {len(documents)} documents and {len(embeddings)} embeddings")

        if not documents:
            return

        self.init_collection(recreate=False)

        points: list[rest_models.PointStruct] = []
        for doc, vector in zip(documents, embeddings, strict=True):
            # Generate deterministic UUID from doc_id for point ID
            point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, doc.doc_id))
            payload = {
                "doc_id": doc.doc_id,
                "doc_type": doc.doc_type,
                "title": doc.title,
                "summary": doc.summary,
                "identifiers": doc.identifiers.model_dump(),
                "tags": doc.tags,
                "source": doc.source.model_dump(),
            }
            points.append(
                rest_models.PointStruct(
                    id=point_id,
                    vector=vector,
                    payload=payload,
                )
            )

        # Batch upsert in chunks of 100
        batch_size = 100
        for i in range(0, len(points), batch_size):
            batch = points[i : i + batch_size]
            self.client.upsert(
                collection_name=self.collection_name,
                points=batch,
            )

    def search(
        self,
        query_vector: list[float],
        top_k: int = 20,
        doc_type: str | None = None,
    ) -> list[VectorSearchResult]:
        """Query nearest neighbor documents using cosine similarity."""
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

        # In qdrant-client >= 1.9, query_points or search can be used
        results = self.client.query_points(
            collection_name=self.collection_name,
            query=query_vector,
            query_filter=query_filter,
            limit=top_k,
            with_payload=True,
            with_vectors=True,
        ).points

        search_results: list[VectorSearchResult] = []
        for point in results:
            payload = point.payload or {}
            vector = point.vector if isinstance(point.vector, list) else []
            search_results.append(
                VectorSearchResult(
                    doc_id=str(payload.get("doc_id", point.id)),
                    score=float(point.score if point.score is not None else 0.0),
                    vector=list(vector) if vector is not None else [],
                    payload=payload,
                )
            )

        return search_results
