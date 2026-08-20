"""Tests for FastEmbed offline semantic embedding client."""

import numpy as np
import pytest

from src.retrieval.embeddings.client import EmbeddingClient


def test_fastembed_initialization_and_dimension() -> None:
    """Verify FastEmbed initializes with 384-dimensional default model."""
    client = EmbeddingClient(provider="fastembed")
    assert client.provider == "fastembed"
    assert client.dimension == 384
    assert client.model == "sentence-transformers/all-MiniLM-L6-v2"


def test_fastembed_generates_valid_semantic_embeddings() -> None:
    """Verify FastEmbed generates normalized vectors and preserves true semantic similarity."""
    client = EmbeddingClient(provider="fastembed")

    texts = [
        "SQL injection vulnerability in user input database query",
        "Cross-site scripting flaw in HTML DOM rendering and innerHTML",
    ]
    vectors = client.embed_texts(texts)

    assert len(vectors) == 2
    assert len(vectors[0]) == 384
    assert len(vectors[1]) == 384

    # Check L2 normalization (norm should be ~1.0)
    norm0 = np.linalg.norm(vectors[0])
    norm1 = np.linalg.norm(vectors[1])
    assert pytest.approx(norm0, abs=1e-3) == 1.0
    assert pytest.approx(norm1, abs=1e-3) == 1.0

    # Semantic similarity test
    query = "database query sql attack"
    q_vec = np.array(client.embed_query(query))
    sim_sql = float(np.dot(q_vec, np.array(vectors[0])))
    sim_xss = float(np.dot(q_vec, np.array(vectors[1])))

    # SQL query must match SQL text significantly higher than XSS
    assert sim_sql > sim_xss
    assert sim_sql > 0.4


def test_fastembed_handles_empty_list() -> None:
    """Verify embed_texts returns empty list when given empty input."""
    client = EmbeddingClient(provider="fastembed")
    assert client.embed_texts([]) == []
