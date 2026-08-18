import json
from pathlib import Path

from typer.testing import CliRunner

from src.retrieval import cli
from src.retrieval.service import KnowledgeSearchService

runner = CliRunner()


def test_search_json_is_machine_readable(canonical_index: Path, monkeypatch: object) -> None:
    monkeypatch.setattr(cli, "KnowledgeSearchService", lambda: KnowledgeSearchService(canonical_index))
    result = runner.invoke(cli.app, ["search", "CWE89", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["query"] == "CWE89"
    assert payload["normalized_query"] == "CWE-89"
    assert payload["results"][0]["doc_id"] == "cwe-89"
    assert "score" in payload["results"][0]
    assert "confidence" not in payload["results"][0]


def test_search_doc_type_filter(canonical_index: Path, monkeypatch: object) -> None:
    monkeypatch.setattr(cli, "KnowledgeSearchService", lambda: KnowledgeSearchService(canonical_index))
    result = runner.invoke(cli.app, ["search", "IDOR", "--doc-type", "cwe"])
    assert result.exit_code == 0
    assert "cwe-639" in result.stdout
    assert "example-idor" not in result.stdout


def test_inspect_reads_full_canonical_document() -> None:
    result = runner.invoke(cli.app, ["inspect", "cwe-89"])
    assert result.exit_code == 0
    assert '"doc_id": "cwe-89"' in result.stdout
    assert '"source"' in result.stdout


def test_invalid_top_k_is_a_usage_error() -> None:
    result = runner.invoke(cli.app, ["search", "XSS", "--top-k", "51"])
    assert result.exit_code != 0
    assert "Invalid value" in result.stdout + result.stderr


def test_clean_removes_only_configured_generated_files(tmp_path: Path, monkeypatch: object) -> None:
    documents = tmp_path / "documents.jsonl"
    manifest = tmp_path / "manifest.json"
    index = tmp_path / "knowledge.db"
    temporary = tmp_path / "knowledge.db.tmp"
    raw = tmp_path / "raw-source.yml"
    for path in (documents, manifest, index, temporary, raw):
        path.write_text("test", encoding="utf-8")
    monkeypatch.setattr(cli, "DOCUMENTS_PATH", documents)
    monkeypatch.setattr(cli, "MANIFEST_PATH", manifest)
    monkeypatch.setattr(cli, "INDEX_PATH", index)
    monkeypatch.setattr(cli, "INDEX_TEMP_PATH", temporary)
    result = runner.invoke(cli.app, ["clean"])
    assert result.exit_code == 0
    assert not any(path.exists() for path in (documents, manifest, index, temporary))
    assert raw.exists()
