"""Cloud Embedding Client for generating dense vector embeddings."""

import hashlib
import os
from typing import Literal

import numpy as np


class EmbeddingClient:
    """Client for generating dense text embeddings with cloud providers or offline testing."""

    def __init__(
        self,
        provider: Literal["openai", "gemini", "mock"] = "openai",
        model: str | None = None,
        dimension: int = 1536,
    ) -> None:
        self.provider = provider
        self.dimension = dimension
        self.api_key = (
            os.getenv("EMBEDDING_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("GEMINI_API_KEY")
            or ""
        )
        self.base_url = (
            os.getenv("EMBEDDING_BASE_URL")
            or os.getenv("OPENAI_BASE_URL")
            or None
        )
        self.model = (
            model
            or os.getenv("EMBEDDING_MODEL")
            or ("text-embedding-3-small" if provider == "openai" else "text-embedding-004")
        )

        if not self.api_key or os.getenv("SENTINEL_OFFLINE_EMBEDDINGS") == "1":
            self.provider = "mock"

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Generate normalized vector embeddings for a list of text passages using the configured model."""
        if not texts:
            return []

        if self.provider == "mock" or not self.api_key:
            return [self._deterministic_pseudo_embedding(t) for t in texts]

        try:
            import openai

            client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url)
            embeddings: list[list[float]] = []
            batch_size = 100
            for i in range(0, len(texts), batch_size):
                batch = texts[i : i + batch_size]
                response = client.embeddings.create(input=batch, model=self.model)
                embeddings.extend([item.embedding for item in response.data])
            return embeddings
        except (ImportError, RuntimeError, ValueError, OSError) as error:
            if os.getenv("SENTINEL_OFFLINE_EMBEDDINGS") == "1":
                return [self._deterministic_pseudo_embedding(t) for t in texts]
            raise RuntimeError(f"Embedding model API request failed for model '{self.model}': {error}") from error

    def embed_query(self, query: str) -> list[float]:
        """Generate embedding vector for a single query."""
        results = self.embed_texts([query])
        return results[0]

    def _deterministic_pseudo_embedding(self, text: str) -> list[float]:
        """Generate a deterministic, normalized pseudo-embedding vector for offline testing."""
        seed = int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)
        rng = np.random.default_rng(seed)
        vector = rng.standard_normal(self.dimension)
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
        return vector.tolist()
