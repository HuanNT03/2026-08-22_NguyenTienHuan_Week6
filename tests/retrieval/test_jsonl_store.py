import json
from pathlib import Path

import pytest

from src.retrieval.models import KnowledgeDocument
from src.retrieval.storage import jsonl_store
from src.retrieval.storage.jsonl_store import read_documents, serialize_documents, sha256_bytes, write_documents


def _document(doc_id: str) -> KnowledgeDocument:
    return KnowledgeDocument.model_validate(
        {
            "doc_id": doc_id,
            "doc_type": "cwe",
            "title": doc_id.upper(),
            "aliases": [],
            "summary": "Summary",
            "content": "Content",
            "identifiers": {"cwe": [], "owasp": [], "semgrep": [], "zap": []},
            "tags": [],
            "source": {"name": "Fixture", "raw_path": f"fixtures/{doc_id}.txt"},
        }
    )


def test_serialization_is_sorted_stable_and_newline_terminated() -> None:
    value = serialize_documents([_document("cwe-2"), _document("cwe-1")])
    lines = value.decode().splitlines()
    assert [json.loads(line)["doc_id"] for line in lines] == ["cwe-1", "cwe-2"]
    assert value.endswith(b"\n")
    assert not any(line.endswith(" ") for line in lines)
    assert value == serialize_documents([_document("cwe-2"), _document("cwe-1")])


def test_write_hashes_exact_bytes_and_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "documents.jsonl"
    digest = write_documents(path, [_document("cwe-1")])
    assert digest == sha256_bytes(path.read_bytes())
    assert [document.doc_id for document in read_documents(path)] == ["cwe-1"]


def test_atomic_write_failure_preserves_old_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "documents.jsonl"
    path.write_bytes(b"old\n")

    def fail_replace(source: Path, destination: Path) -> None:
        raise OSError(f"cannot replace {source} with {destination}")

    monkeypatch.setattr(jsonl_store.os, "replace", fail_replace)
    with pytest.raises(OSError, match="cannot replace"):
        jsonl_store.atomic_write_bytes(path, b"new\n")
    assert path.read_bytes() == b"old\n"
    assert not (tmp_path / ".documents.jsonl.tmp").exists()
