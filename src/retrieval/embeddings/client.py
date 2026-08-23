"""Cloud & Local ONNX Embedding Client for generating dense vector embeddings."""

import hashlib
import os
from typing import Any, Literal

import numpy as np

from src.retrieval.exceptions import EmbeddingAPIError, EmbeddingConfigurationError

# Default dimensions per provider/model
_PROVIDER_DEFAULTS = {
    "openai": ("text-embedding-3-small", 1536),
    "dashscope": ("text-embedding-v4", 1024),
    "fastembed": ("sentence-transformers/all-MiniLM-L6-v2", 384),
    "mock": ("mock-gaussian", 1536),
}

_FASTEMBED_CACHE: dict[str, Any] = {}


class EmbeddingClient:
    """Client for generating dense text embeddings with cloud providers, FastEmbed ONNX, or offline mock."""

    def __init__(
        self,
        provider: Literal["openai", "dashscope", "fastembed", "mock"] | None = None,
        model: str | None = None,
        dimension: int | None = None,
    ) -> None:
        """Initialize the EmbeddingClient with provider, model, and vector dimension.

        Args:
            provider: Backend provider name ('openai', 'dashscope', 'fastembed', or 'mock').
            model: Name of the embedding model. If None, falls back to EMBEDDING_MODEL env or provider default.
            dimension: Default vector dimension. Overridden by EMBEDDING_DIMENSION env var if present.
        """
        # 1. Resolve Provider
        if provider:
            resolved_provider = provider
        elif os.getenv("SENTINEL_OFFLINE_EMBEDDINGS") == "1":
            resolved_provider = "mock"
        else:
            env_provider = os.getenv("EMBEDDING_PROVIDER", "").strip().lower()
            if env_provider in ("openai", "dashscope", "fastembed", "mock"):
                resolved_provider = env_provider
            else:
                api_key = (
                    os.getenv("EMBEDDING_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY") or ""
                )
                base_url = os.getenv("EMBEDDING_BASE_URL") or ""
                if api_key:
                    resolved_provider = "dashscope" if ("aliyuncs" in base_url or "dashscope" in base_url) else "openai"
                else:
                    resolved_provider = "fastembed"

        self.provider: Literal["openai", "dashscope", "fastembed", "mock"] = resolved_provider

        # 2. Resolve Model and Dimension defaults
        default_model, default_dim = _PROVIDER_DEFAULTS.get(
            self.provider, ("sentence-transformers/all-MiniLM-L6-v2", 384)
        )

        if model is not None:
            self.model = model
        elif self.provider == "fastembed":
            env_model = os.getenv("EMBEDDING_MODEL")
            if env_model and ("sentence-transformers" in env_model or "bge" in env_model or "nomic" in env_model):
                self.model = env_model
            else:
                self.model = default_model
        else:
            self.model = os.getenv("EMBEDDING_MODEL") or default_model

        if dimension is not None:
            self.dimension = dimension
        elif self.provider == "fastembed":
            self.dimension = default_dim
        else:
            env_dim = os.getenv("EMBEDDING_DIMENSION")
            if env_dim and env_dim.strip().isdigit():
                self.dimension = int(env_dim.strip())
            else:
                self.dimension = default_dim

        self.api_key = (
            os.getenv("EMBEDDING_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY") or ""
        )
        self.base_url = os.getenv("EMBEDDING_BASE_URL") or os.getenv("OPENAI_BASE_URL") or None
        self._fastembed_instance: Any = None

    def _ensure_configured(self) -> None:
        """Validate that all required embedding configurations are present when running online."""
        if self.provider in ("mock", "fastembed"):
            return
        if not self.api_key or not self.api_key.strip():
            raise EmbeddingConfigurationError(
                "Missing embedding API key. Please configure EMBEDDING_API_KEY (or OPENAI_API_KEY) in .env "
                "or set EMBEDDING_PROVIDER=fastembed to use local offline embedding."
            )
        if not self.model or not self.model.strip():
            raise EmbeddingConfigurationError("Missing embedding model name. Please configure EMBEDDING_MODEL in .env.")

    def _embed_fastembed(self, texts: list[str]) -> list[list[float]]:
        """Generate normalized embeddings using local FastEmbed ONNX runtime."""
        if self.model not in _FASTEMBED_CACHE:
            from fastembed import TextEmbedding

            _FASTEMBED_CACHE[self.model] = TextEmbedding(model_name=self.model)

        self._fastembed_instance = _FASTEMBED_CACHE[self.model]
        embeddings_generator = self._fastembed_instance.embed(texts)
        return [vec.tolist() for vec in embeddings_generator]

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Generate normalized vector embeddings for a list of text passages using the configured model."""
        if not texts:
            return []

        if self.provider == "mock":
            return [self._deterministic_pseudo_embedding(t) for t in texts]

        if self.provider == "fastembed":
            return self._embed_fastembed(texts)

        self._ensure_configured()

        try:
            import openai

            client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url)
            embeddings: list[list[float]] = []
            batch_size = 10
            sanitized_texts = [t.strip()[:8000] if t.strip() else "empty" for t in texts]
            for i in range(0, len(sanitized_texts), batch_size):
                batch = sanitized_texts[i : i + batch_size]
                response = client.embeddings.create(input=batch, model=self.model)
                embeddings.extend([item.embedding for item in response.data])
            return embeddings
        except Exception as error:
            raise EmbeddingAPIError(
                f"Embedding model API request failed for model '{self.model}' "
                f"(base_url: {self.base_url or 'default OpenAI endpoint'}): {error}. "
                "Please verify your EMBEDDING_API_KEY, EMBEDDING_BASE_URL, and network connection in .env."
            ) from error

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
