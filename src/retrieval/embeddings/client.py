"""Cloud Embedding Client for generating vector embeddings."""

import hashlib
import os
from typing import Literal

import numpy as np


class EmbeddingClient:
    """Client for generating dense text embeddings with cloud providers or offline fallback."""

    def __init__(
        self,
        provider: Literal["openai", "gemini", "mock"] = "openai",
        model: str | None = None,
        dimension: int = 1536,
    ) -> None:
        self.provider = provider
        self.dimension = dimension
        self.model = model or ("text-embedding-3-small" if provider == "openai" else "text-embedding-004")
        self.api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY") or ""

        if not self.api_key or os.getenv("SENTINEL_OFFLINE_EMBEDDINGS") == "1":
            self.provider = "mock"

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Generate normalized vector embeddings for a list of text passages."""
        if not texts:
            return []

        if self.provider == "mock" or not self.api_key:
            return [self._deterministic_pseudo_embedding(t) for t in texts]

        try:
            import openai

            client = openai.OpenAI(api_key=self.api_key)
            # Batch embeddings in chunks of 100
            embeddings: list[list[float]] = []
            batch_size = 100
            for i in range(0, len(texts), batch_size):
                batch = texts[i : i + batch_size]
                response = client.embeddings.create(input=batch, model=self.model)
                embeddings.extend([item.embedding for item in response.data])
            return embeddings
        except (ImportError, RuntimeError, ValueError, OSError):
            # Fallback to deterministic pseudo embeddings if network/API fails
            return [self._deterministic_pseudo_embedding(t) for t in texts]

    def embed_query(self, query: str) -> list[float]:
        """Generate embedding vector for a single query."""
        results = self.embed_texts([query])
        return results[0]

    def _deterministic_pseudo_embedding(self, text: str) -> list[float]:
        """Generate a deterministic, normalized pseudo-embedding vector for offline testing."""
        # Use SHA-256 seed to produce reproducible floats
        seed = int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)
        rng = np.random.default_rng(seed)
        vector = rng.standard_normal(self.dimension)
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
        return vector.tolist()
