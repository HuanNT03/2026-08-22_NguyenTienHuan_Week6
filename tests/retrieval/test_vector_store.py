"""Unit tests for EmbeddingClient and QdrantVectorStore."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.retrieval.embeddings.client import EmbeddingClient
from src.retrieval.exceptions import EmbeddingAPIError, EmbeddingConfigurationError
from src.retrieval.models import KnowledgeDocument, KnowledgeIdentifiers, KnowledgeSource
from src.retrieval.vector.qdrant_store import QdrantVectorStore


def test_embedding_client_generates_deterministic_normalized_vectors() -> None:
    client = EmbeddingClient(provider="mock", dimension=128)
    vec1 = client.embed_query("SQL Injection Prevention")
    vec2 = client.embed_query("SQL Injection Prevention")
    vec3 = client.embed_query("Cross Site Scripting")

    assert len(vec1) == 128
    assert vec1 == vec2
    assert vec1 != vec3


def test_embedding_client_raises_configuration_error_when_api_key_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_OFFLINE_EMBEDDINGS", raising=False)
    monkeypatch.delenv("EMBEDDING_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    client = EmbeddingClient(provider="openai")
    with pytest.raises(EmbeddingConfigurationError, match="Missing embedding API key"):
        client.embed_query("test query")


def test_embedding_client_raises_api_error_when_remote_api_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_OFFLINE_EMBEDDINGS", raising=False)
    monkeypatch.setenv("EMBEDDING_API_KEY", "dummy-key")

    client = EmbeddingClient(provider="openai", model="test-model")

    mock_openai = MagicMock()
    mock_openai.OpenAI.return_value.embeddings.create.side_effect = RuntimeError("Connection timeout")
    monkeypatch.setattr("openai.OpenAI", mock_openai.OpenAI)

    with pytest.raises(EmbeddingAPIError, match="Embedding model API request failed for model 'test-model'"):
        client.embed_query("test query")


def test_qdrant_vector_store_upsert_and_search(tmp_path: Path) -> None:
    store = QdrantVectorStore(storage_path=tmp_path / "qdrant", collection_name="test_kb", dimension=64)
    client = EmbeddingClient(provider="mock", dimension=64)

    doc1 = KnowledgeDocument(
        doc_id="test-doc-1",
        doc_type="cwe",
        title="CWE-89: SQL Injection",
        aliases=["SQL Injection"],
        summary="SQL injection vulnerability overview.",
        content="Detailed content about SQL injection.",
        identifiers=KnowledgeIdentifiers(cwe=["CWE-89"]),
        tags=["sql", "injection"],
        source=KnowledgeSource(name="CWE", version="4.14", raw_path="699.csv", source_locator="89"),
    )
    doc2 = KnowledgeDocument(
        doc_id="test-doc-2",
        doc_type="vulnerability_example",
        title="Node.js SQL Injection Example",
        aliases=["SQLi Example"],
        summary="Example of vulnerable and safe SQL in Node.js.",
        content="const query = `SELECT * FROM users`;",
        identifiers=KnowledgeIdentifiers(cwe=["CWE-89"]),
        tags=["nodejs", "sql"],
        source=KnowledgeSource(name="Examples", version="1.0", raw_path="sql.yml", source_locator="sql"),
    )

    embeddings = client.embed_texts([doc1.content, doc2.content])
    store.upsert_documents([doc1, doc2], embeddings)

    query_vec = client.embed_query("SQL query database")
    results = store.search(query_vec, top_k=5)

    assert len(results) == 2
    assert {r.doc_id for r in results} == {"test-doc-1", "test-doc-2"}
    assert all(len(r.vector) == 64 for r in results)
    assert all(r.payload["doc_type"] in ("cwe", "vulnerability_example") for r in results)
