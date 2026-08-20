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


def test_embedding_dimension_read_from_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("EMBEDDING_DIMENSION", "1024")
    client = EmbeddingClient(provider="mock")
    assert client.dimension == 1024
    vec = client.embed_query("test query")
    assert len(vec) == 1024

    store = QdrantVectorStore(storage_path=tmp_path / "qdrant_custom")
    assert store.dimension == 1024


def test_qdrant_vector_store_upsert_chunks_and_aggregate_parents(tmp_path: Path) -> None:
    from src.retrieval.chunking.markdown_chunker import DocumentChunk

    store = QdrantVectorStore(storage_path=tmp_path / "qdrant_chunks", collection_name="test_chunks", dimension=64)
    client = EmbeddingClient(provider="mock", dimension=64)

    # 3 child chunks for parent-1 and 1 chunk for parent-2
    chunks = [
        DocumentChunk(
            chunk_id="owasp-2025-a01#description",
            parent_doc_id="owasp-2025-a01",
            parent_title="A01:2025 Broken Access Control",
            section_title="Description",
            content="# A01:2025 Broken Access Control\n\n## Description\n\nAccess control overview.",
            doc_type="owasp_category",
        ),
        DocumentChunk(
            chunk_id="owasp-2025-a01#prevention",
            parent_doc_id="owasp-2025-a01",
            parent_title="A01:2025 Broken Access Control",
            section_title="Prevention",
            content="# A01:2025 Broken Access Control\n\n## Prevention\n\nRBAC and ownership checks.",
            doc_type="owasp_category",
        ),
        DocumentChunk(
            chunk_id="owasp-2025-a01#scenarios",
            parent_doc_id="owasp-2025-a01",
            parent_title="A01:2025 Broken Access Control",
            section_title="Attack Scenarios",
            content="# A01:2025 Broken Access Control\n\n## Attack Scenarios\n\nAdmin parameter tampering.",
            doc_type="owasp_category",
        ),
        DocumentChunk(
            chunk_id="cwe-89#main",
            parent_doc_id="cwe-89",
            parent_title="CWE-89: SQL Injection",
            section_title="Overview",
            content="# CWE-89: SQL Injection\n\nSQL query injection.",
            doc_type="cwe",
        ),
    ]

    embeddings = client.embed_texts([c.content for c in chunks])
    store.upsert_chunks(chunks, embeddings)

    # Search should aggregate 3 chunks of owasp-2025-a01 into 1 parent result
    query_vec = client.embed_query("broken access control prevention")
    results = store.search_parents(query_vec, top_k=5)

    assert len(results) == 2
    assert {r.doc_id for r in results} == {"owasp-2025-a01", "cwe-89"}
    owasp_res = next(r for r in results if r.doc_id == "owasp-2025-a01")
    assert owasp_res.matched_section in ("Description", "Prevention", "Attack Scenarios")
    assert "A01:2025 Broken Access Control" in owasp_res.matched_snippet


