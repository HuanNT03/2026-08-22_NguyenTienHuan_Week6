"""Unit tests cho các bridge module thuộc src/app."""

import json
from pathlib import Path

import pytest

from src.app.agent_bridge import (
    get_configured_model,
    list_analyzed_reports,
    load_analysis_report,
)
from src.app.normalizer_bridge import (
    list_normalized_files,
    list_raw_report_files,
    load_unified_findings,
    save_uploaded_report,
)
from src.app.retrieval_bridge import (
    inspect_knowledge_document,
    search_knowledge_base,
)
from src.app.scan_runner import get_supported_scanners, run_scanner


def test_get_supported_scanners():
    scanners = get_supported_scanners()
    assert "semgrep" in scanners
    assert "codeql" in scanners
    assert "zap_baseline" in scanners
    assert "sqlmap" in scanners


def test_get_configured_model():
    model = get_configured_model()
    assert isinstance(model, str)
    assert len(model) > 0


def test_run_scanner_unsupported_tool():
    success, output = run_scanner("invalid_tool_name")
    assert success is False
    assert "không được hỗ trợ" in output


def test_save_uploaded_report(tmp_path: Path):
    file_bytes = b'{"test": "content"}'
    saved_path = save_uploaded_report(
        file_name="semgrep.json",
        file_bytes=file_bytes,
        raw_dir=str(tmp_path),
    )
    assert Path(saved_path).exists()
    assert Path(saved_path).read_bytes() == file_bytes


def test_load_unified_findings_valid(tmp_path: Path):
    jsonl_file = tmp_path / "unified-findings-test.jsonl"
    finding_obj = {"fingerprint": "fp_sha256:v1:12345", "title": "Test Finding"}
    jsonl_file.write_text(json.dumps(finding_obj) + "\n", encoding="utf-8")

    findings = load_unified_findings(str(jsonl_file))
    assert len(findings) == 1
    assert findings[0]["fingerprint"] == "fp_sha256:v1:12345"


def test_load_unified_findings_missing_file():
    with pytest.raises(FileNotFoundError):
        load_unified_findings("non_existent_file.jsonl")


def test_list_normalized_files(tmp_path: Path):
    jsonl_file = tmp_path / "unified-findings-20260807T120000Z.jsonl"
    jsonl_file.write_text("{}\n", encoding="utf-8")
    files = list_normalized_files(output_dir=str(tmp_path))
    assert len(files) == 1
    assert files[0] == str(jsonl_file)


def test_search_knowledge_base_empty_query():
    results = search_knowledge_base("")
    assert results == []


def test_search_knowledge_base_real_index():
    index_path = Path("knowledge-base/index/knowledge.db")
    if not index_path.exists():
        pytest.skip("SQLite knowledge.db chưa được build, bỏ qua integration test này.")

    results = search_knowledge_base("SQL Injection", top_k=3, index_path=index_path)
    assert isinstance(results, list)
    if results:
        assert "doc_id" in results[0]
        assert "title" in results[0]


def test_inspect_knowledge_document_real_index():
    index_path = Path("knowledge-base/index/knowledge.db")
    if not index_path.exists():
        pytest.skip("SQLite knowledge.db chưa được build, bỏ qua integration test này.")

    doc = inspect_knowledge_document("cwe-89", index_path=index_path)
    assert doc is not None
    assert doc["doc_id"] == "cwe-89"


def test_load_analysis_report_valid(tmp_path: Path):
    report_file = tmp_path / "security-analysis-report-test.jsonl"
    entry_obj = {"analysis_id": "analysis_123", "title": "AI Risk Title"}
    report_file.write_text(json.dumps(entry_obj) + "\n", encoding="utf-8")

    entries = load_analysis_report(str(report_file))
    assert len(entries) == 1
    assert entries[0]["analysis_id"] == "analysis_123"


def test_list_raw_report_files(tmp_path: Path):
    raw_file = tmp_path / "semgrep.json"
    raw_file.write_text("{}", encoding="utf-8")
    files = list_raw_report_files(raw_dir=str(tmp_path))
    assert len(files) == 1
    assert files[0]["name"] == "semgrep.json"
    assert files[0]["path"] == str(raw_file)
    assert "size" in files[0]
    assert "mtime" in files[0]


def test_list_raw_report_files_missing_dir():
    files = list_raw_report_files(raw_dir="non_existent_raw_dir")
    assert files == []


def test_search_knowledge_base_with_mode():
    index_path = Path("knowledge-base/index/knowledge.db")
    if not index_path.exists():
        pytest.skip("SQLite knowledge.db chưa được build, bỏ qua integration test này.")

    # Test keyword mode
    kw_results = search_knowledge_base("SQL Injection", top_k=2, index_path=index_path, mode="keyword")
    assert isinstance(kw_results, list)

    # Test hybrid mode (default)
    hy_results = search_knowledge_base("SQL Injection", top_k=2, index_path=index_path, mode="hybrid")
    assert isinstance(hy_results, list)

