"""Atomic SQLite external-content FTS5 index construction."""

import json
import sqlite3
from pathlib import Path

from src.retrieval.config import DOCUMENTS_PATH, FTS_COLUMNS, INDEX_PATH, MANIFEST_PATH
from src.retrieval.exceptions import KnowledgeIndexBuildError, UnsupportedSQLiteError
from src.retrieval.models import KnowledgeDocument
from src.retrieval.storage.jsonl_store import read_documents, sha256_bytes

DOCUMENTS_SCHEMA = """
CREATE TABLE documents (
    rowid INTEGER PRIMARY KEY,
    doc_id TEXT NOT NULL UNIQUE,
    doc_type TEXT NOT NULL,
    title TEXT NOT NULL,
    aliases_json TEXT NOT NULL,
    aliases_text TEXT NOT NULL,
    identifiers_json TEXT NOT NULL,
    identifiers_text TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    tags_text TEXT NOT NULL,
    summary TEXT NOT NULL,
    content TEXT NOT NULL,
    source_json TEXT NOT NULL
)
"""


def validate_sqlite_capabilities() -> None:
    """Require working SQLite JSON functions and FTS5 from the active Python runtime."""
    connection = sqlite3.connect(":memory:")
    try:
        row = connection.execute(
            "SELECT value FROM json_each('[1, 2, 3]') LIMIT 1"
        ).fetchone()
        if row is None or row[0] != 1:
            raise UnsupportedSQLiteError("SQLite JSON support returned an unexpected result.")
        connection.execute("CREATE VIRTUAL TABLE fts_smoke_test USING fts5(content)")
        connection.execute("INSERT INTO fts_smoke_test(content) VALUES ('SQL Injection')")
        match = connection.execute(
            "SELECT rowid FROM fts_smoke_test WHERE fts_smoke_test MATCH ?",
            ('"SQL" "Injection"',),
        ).fetchone()
        if match is None:
            raise UnsupportedSQLiteError("SQLite FTS5 smoke search failed.")
    except sqlite3.OperationalError as error:
        raise UnsupportedSQLiteError(
            "The active Python SQLite runtime must support JSON functions and FTS5."
        ) from error
    finally:
        connection.close()


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _identifier_values(document: KnowledgeDocument) -> list[str]:
    identifiers = document.identifiers
    return [*identifiers.cwe, *identifiers.owasp, *identifiers.semgrep, *identifiers.zap]


def _insert_document(connection: sqlite3.Connection, document: KnowledgeDocument) -> None:
    aliases = list(document.aliases)
    identifiers = document.identifiers.model_dump(mode="json")
    tags = list(document.tags)
    connection.execute(
        """
        INSERT INTO documents (
            doc_id, doc_type, title, aliases_json, aliases_text,
            identifiers_json, identifiers_text, tags_json, tags_text,
            summary, content, source_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            document.doc_id,
            document.doc_type,
            document.title,
            _json(aliases),
            " ".join(aliases),
            _json(identifiers),
            " ".join(_identifier_values(document)),
            _json(tags),
            " ".join(tags),
            document.summary,
            document.content,
            _json(document.source.model_dump(mode="json", exclude_none=True)),
        ),
    )


def _create_fts(connection: sqlite3.Connection) -> None:
    columns = ",\n    ".join(FTS_COLUMNS)
    connection.execute(
        f"""
        CREATE VIRTUAL TABLE knowledge_fts USING fts5(
            {columns},
            content='documents',
            content_rowid='rowid',
            tokenize='unicode61'
        )
        """
    )


def _validate_manifest(documents_path: Path, manifest_path: Path, document_count: int) -> None:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise KnowledgeIndexBuildError(f"Unable to read canonical manifest {manifest_path}: {error}") from error
    actual_hash = sha256_bytes(documents_path.read_bytes())
    if manifest.get("documents_sha256") != actual_hash:
        raise KnowledgeIndexBuildError(
            f"Manifest hash mismatch for {documents_path}: expected {manifest.get('documents_sha256')}, found {actual_hash}"
        )
    if manifest.get("document_count") != document_count:
        raise KnowledgeIndexBuildError(
            f"Manifest count mismatch: expected {manifest.get('document_count')}, found {document_count}"
        )


def _validate_index(connection: sqlite3.Connection, documents: list[KnowledgeDocument]) -> None:
    count = connection.execute("SELECT count(*) FROM documents").fetchone()
    if count is None or count[0] != len(documents):
        raise KnowledgeIndexBuildError("SQLite documents count does not match canonical JSONL.")
    first_token = next(
        (token for token in documents[0].title.replace(":", " ").replace("-", " ").split() if token.isalnum()),
        None,
    )
    if first_token is None:
        raise KnowledgeIndexBuildError("Unable to derive an FTS5 validation token.")
    match = connection.execute(
        "SELECT rowid FROM knowledge_fts WHERE knowledge_fts MATCH ? LIMIT 1",
        (f'"{first_token}"',),
    ).fetchone()
    if match is None:
        raise KnowledgeIndexBuildError("SQLite FTS5 validation search returned no result.")


def build_index(
    documents_path: Path = DOCUMENTS_PATH,
    manifest_path: Path = MANIFEST_PATH,
    final_path: Path = INDEX_PATH,
) -> Path:
    """Build a complete index at a temporary path and atomically replace the old database."""
    validate_sqlite_capabilities()
    documents = read_documents(documents_path)
    if not documents:
        raise KnowledgeIndexBuildError(f"Canonical document set is empty: {documents_path}")
    _validate_manifest(documents_path, manifest_path, len(documents))
    final_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = final_path.with_suffix(final_path.suffix + ".tmp")
    if temporary_path.exists():
        temporary_path.unlink()
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(temporary_path)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(DOCUMENTS_SCHEMA)
        _create_fts(connection)
        with connection:
            for document in documents:
                _insert_document(connection, document)
            connection.execute("INSERT INTO knowledge_fts(knowledge_fts) VALUES ('rebuild')")
        _validate_index(connection, documents)
        connection.close()
        connection = None
        temporary_path.replace(final_path)
        return final_path
    except Exception as error:
        if isinstance(error, KnowledgeIndexBuildError):
            raise
        raise KnowledgeIndexBuildError(f"Failed to build SQLite knowledge index {final_path}: {error}") from error
    finally:
        if connection is not None:
            connection.close()
        if temporary_path.exists():
            temporary_path.unlink()
