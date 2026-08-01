import json
import sqlite3
from pathlib import Path

import pytest

from src.retrieval.exceptions import KnowledgeIndexBuildError
from src.retrieval.indexers import sqlite_fts
from src.retrieval.indexers.sqlite_fts import build_index
from src.retrieval.models import KnowledgeDocument
from src.retrieval.storage.jsonl_store import sha256_bytes, write_documents


def _document(doc_id: str, content: str = "original alpha content") -> KnowledgeDocument:
    return KnowledgeDocument.model_validate(
        {
            "doc_id": doc_id,
            "doc_type": "scanner_document",
            "title": f"Original Alpha {doc_id}",
            "aliases": ["Alpha"],
            "summary": "Original alpha summary",
            "content": content,
            "identifiers": {"cwe": [], "owasp": [], "semgrep": [], "zap": []},
            "tags": ["fixture"],
            "source": {"name": "Fixture", "raw_path": f"fixtures/{doc_id}.md"},
        }
    )


def _sources(tmp_path: Path, documents: list[KnowledgeDocument]) -> tuple[Path, Path]:
    documents_path = tmp_path / "documents.jsonl"
    manifest_path = tmp_path / "manifest.json"
    digest = write_documents(documents_path, documents)
    manifest_path.write_text(
        json.dumps({"document_count": len(documents), "documents_sha256": digest}),
        encoding="utf-8",
    )
    return documents_path, manifest_path


def test_external_content_index_rebuilds_and_returns_metadata(tmp_path: Path) -> None:
    documents_path, manifest_path = _sources(tmp_path, [_document("fixture-one"), _document("fixture-two")])
    index_path = tmp_path / "knowledge.db"
    build_index(documents_path, manifest_path, index_path)
    connection = sqlite3.connect(index_path)
    try:
        row = connection.execute(
            """
            SELECT d.doc_id, d.source_json
            FROM knowledge_fts JOIN documents AS d ON d.rowid = knowledge_fts.rowid
            WHERE knowledge_fts MATCH 'alpha'
            ORDER BY d.doc_id LIMIT 1
            """
        ).fetchone()
        assert row is not None
        assert row[0] == "fixture-one"
        assert json.loads(row[1])["name"] == "Fixture"

        connection.execute("UPDATE documents SET content = 'updated omega content' WHERE doc_id = 'fixture-one'")
        connection.execute("INSERT INTO knowledge_fts(knowledge_fts) VALUES ('rebuild')")
        assert connection.execute(
            "SELECT count(*) FROM knowledge_fts WHERE knowledge_fts MATCH 'omega'"
        ).fetchone() == (1,)

        connection.execute("DELETE FROM documents WHERE doc_id = 'fixture-one'")
        connection.execute("INSERT INTO knowledge_fts(knowledge_fts) VALUES ('rebuild')")
        assert connection.execute(
            "SELECT count(*) FROM knowledge_fts WHERE knowledge_fts MATCH 'omega'"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_manifest_hash_mismatch_is_rejected(tmp_path: Path) -> None:
    documents_path, manifest_path = _sources(tmp_path, [_document("fixture-one")])
    manifest_path.write_text('{"document_count":1,"documents_sha256":"sha256:bad"}', encoding="utf-8")
    with pytest.raises(KnowledgeIndexBuildError, match="Manifest hash mismatch"):
        build_index(documents_path, manifest_path, tmp_path / "knowledge.db")


def test_failed_build_does_not_replace_existing_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    documents_path, manifest_path = _sources(tmp_path, [_document("fixture-one")])
    index_path = tmp_path / "knowledge.db"
    index_path.write_bytes(b"previous index")

    def fail_validation(connection: sqlite3.Connection, documents: list[KnowledgeDocument]) -> None:
        raise KnowledgeIndexBuildError("forced validation failure")

    monkeypatch.setattr(sqlite_fts, "_validate_index", fail_validation)
    with pytest.raises(KnowledgeIndexBuildError, match="forced validation failure"):
        build_index(documents_path, manifest_path, index_path)
    assert index_path.read_bytes() == b"previous index"
    assert not (tmp_path / "knowledge.db.tmp").exists()


def test_manifest_hash_helper_uses_exact_document_bytes(tmp_path: Path) -> None:
    documents_path, _ = _sources(tmp_path, [_document("fixture-one")])
    assert sha256_bytes(documents_path.read_bytes()).startswith("sha256:")
