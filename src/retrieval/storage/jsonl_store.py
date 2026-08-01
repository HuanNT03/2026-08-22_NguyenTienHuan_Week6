"""Deterministic JSONL serialization and loading."""

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from src.retrieval.exceptions import InvalidKnowledgeDocumentError
from src.retrieval.models import KnowledgeDocument


def serialize_documents(documents: list[KnowledgeDocument]) -> bytes:
    """Serialize documents sorted by ID as stable UTF-8 JSON Lines bytes."""
    ordered = sorted(documents, key=lambda document: document.doc_id)
    lines = [
        json.dumps(
            document.to_canonical_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        for document in ordered
    ]
    return (("\n".join(lines) + "\n") if lines else "").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    """Return a namespaced SHA-256 digest for exact bytes."""
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def atomic_write_bytes(path: Path, value: bytes) -> None:
    """Atomically replace a file using a temporary sibling path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_bytes(value)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_documents(path: Path, documents: list[KnowledgeDocument]) -> str:
    """Write canonical JSONL atomically and return its exact byte hash."""
    value = serialize_documents(documents)
    atomic_write_bytes(path, value)
    return sha256_bytes(value)


def read_documents(path: Path) -> list[KnowledgeDocument]:
    """Read and validate canonical documents with useful JSONL line errors."""
    documents: list[KnowledgeDocument] = []
    try:
        handle = path.open(encoding="utf-8")
    except OSError as error:
        raise InvalidKnowledgeDocumentError(f"Unable to read canonical documents {path}: {error}") from error
    with handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                raise InvalidKnowledgeDocumentError(f"{path}:{line_number}: blank JSONL line")
            try:
                value: Any = json.loads(line)
            except json.JSONDecodeError as error:
                raise InvalidKnowledgeDocumentError(f"{path}:{line_number}: invalid JSON: {error.msg}") from error
            try:
                documents.append(KnowledgeDocument.model_validate(value))
            except ValidationError as error:
                raise InvalidKnowledgeDocumentError(
                    f"{path}:{line_number}: invalid knowledge document: {error}"
                ) from error
    return documents
