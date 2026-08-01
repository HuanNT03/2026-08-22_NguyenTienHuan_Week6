import json
from pathlib import Path

from src.retrieval.indexers.sqlite_fts import build_index
from src.retrieval.models import KnowledgeDocument
from src.retrieval.service import KnowledgeSearchService
from src.retrieval.storage.jsonl_store import write_documents


def _document(
    doc_id: str,
    *,
    title: str,
    aliases: list[str] | None = None,
    identifiers: list[str] | None = None,
    content: str = "Reference content",
) -> KnowledgeDocument:
    return KnowledgeDocument.model_validate(
        {
            "doc_id": doc_id,
            "doc_type": "cwe",
            "title": title,
            "aliases": aliases or [],
            "summary": content,
            "content": content,
            "identifiers": {
                "cwe": identifiers or [],
                "owasp": [],
                "semgrep": [],
                "zap": [],
            },
            "tags": [],
            "source": {"name": "Fixture", "raw_path": f"fixtures/{doc_id}.md"},
        }
    )


def _service(tmp_path: Path) -> KnowledgeSearchService:
    documents = [
        _document("rank-identifier", title="Identifier CWE-89 reference", identifiers=["CWE-89"]),
        _document("rank-title-id", title="CWE-89"),
        _document("rank-alias-id", title="Alias CWE 89 reference", aliases=["CWE-89"]),
        _document("rank-title", title="SQL Injection"),
        _document("rank-alias", title="Database weakness", aliases=["SQL Injection"]),
        _document("rank-content", title="Database issue", content="SQL Injection appears in content"),
        _document("rank-needle-strong", title="Needle guide", content="needle"),
        _document("rank-needle-weak", title="Generic guide", content="needle"),
        _document("rank-tie-a", title="Tie A", content="tiephrase"),
        _document("rank-tie-b", title="Tie B", content="tiephrase"),
    ]
    documents_path = tmp_path / "documents.jsonl"
    manifest_path = tmp_path / "manifest.json"
    digest = write_documents(documents_path, documents)
    manifest_path.write_text(
        json.dumps({"document_count": len(documents), "documents_sha256": digest}),
        encoding="utf-8",
    )
    index_path = tmp_path / "knowledge.db"
    build_index(documents_path, manifest_path, index_path)
    return KnowledgeSearchService(index_path)


def test_identifier_beats_title_and_alias(tmp_path: Path) -> None:
    results = _service(tmp_path).search("CWE89", top_k=10)
    relevant = [result for result in results if result.doc_id.startswith("rank-")]
    assert [result.doc_id for result in relevant[:3]] == [
        "rank-identifier",
        "rank-title-id",
        "rank-alias-id",
    ]
    assert [result.exact_match_rank for result in relevant[:3]] == [0, 1, 2]


def test_title_beats_alias_and_alias_beats_content(tmp_path: Path) -> None:
    results = _service(tmp_path).search("SQL Injection", top_k=10)
    assert [result.doc_id for result in results[:3]] == ["rank-title", "rank-alias", "rank-content"]
    assert [result.exact_match_rank for result in results[:3]] == [1, 2, 3]


def test_bm25_breaks_non_exact_tie(tmp_path: Path) -> None:
    results = _service(tmp_path).search("needle", top_k=10)
    assert [result.doc_id for result in results[:2]] == ["rank-needle-strong", "rank-needle-weak"]
    assert results[0].bm25_score < results[1].bm25_score


def test_doc_id_is_final_deterministic_tie_break(tmp_path: Path) -> None:
    results = _service(tmp_path).search("tiephrase", top_k=10)
    assert [result.doc_id for result in results] == ["rank-tie-a", "rank-tie-b"]
