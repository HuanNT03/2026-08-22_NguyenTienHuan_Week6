"""Edge case tests for Security Analysis Agent per AGENTS.md definition of done."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.agent.config import AgentConfig
from src.agent.grouper import load_and_validate_findings
from src.agent.orchestrator import run_analysis


def test_load_and_validate_findings_raises_on_non_existent_file() -> None:
    with pytest.raises(FileNotFoundError):
        load_and_validate_findings(Path("/non/existent/findings.jsonl"))


def test_load_and_validate_findings_raises_on_malformed_json(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.jsonl"
    bad_file.write_text("invalid json line\n", encoding="utf-8")
    with pytest.raises(ValueError, match="contains malformed JSON"):
        load_and_validate_findings(bad_file)


def test_load_and_validate_findings_raises_on_missing_fingerprint(tmp_path: Path) -> None:
    bad_file = tmp_path / "missing_fp.jsonl"
    bad_file.write_text(json.dumps({"title": "SQLi"}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing 'fingerprint' or 'finding_id'"):
        load_and_validate_findings(bad_file)


def test_run_analysis_handles_empty_input(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.jsonl"
    empty_file.write_text("", encoding="utf-8")

    out_dir = tmp_path / "analyzed"
    config = AgentConfig(api_key="mock_key", output_dir=out_dir)

    mock_client = MagicMock()
    mock_kb = MagicMock()

    summary = run_analysis(
        findings_path=empty_file,
        config=config,
        client=mock_client,
        kb_service=mock_kb,
    )

    assert summary["total_input_findings"] == 0
    assert summary["total_report_entries"] == 0
    assert summary["coverage"]["is_complete"]


def test_run_analysis_handles_provider_error(tmp_path: Path) -> None:
    findings_file = tmp_path / "single_finding.jsonl"
    finding_data = {
        "schema_version": "2.0.0",
        "finding_id": "fnd_0123456789abcdef0123456789abcdef",
        "fingerprint": f"fp_sha256:v1:{'c' * 64}",
        "group_key": f"grp_sha256:v1:{'d' * 64}",
        "tool": {"name": "semgrep", "scan_type": "SAST"},
        "title": "SQL Injection",
        "cwe_ids": ["CWE-89"],
        "location": {"kind": "code", "path": "routes/login.ts", "start_line": 34},
        "evidence": {"kind": "code"},
    }
    findings_file.write_text(json.dumps(finding_data) + "\n", encoding="utf-8")

    out_dir = tmp_path / "analyzed"
    config = AgentConfig(api_key="mock_key", max_retries=1, output_dir=out_dir)

    # Mock client that raises API error
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = RuntimeError("OpenAI Provider Connection Error")

    mock_kb = MagicMock()
    mock_kb.search.return_value = []

    summary = run_analysis(
        findings_path=findings_file,
        config=config,
        client=mock_client,
        kb_service=mock_kb,
    )

    # 100% coverage must still pass via fallback error entries
    assert summary["total_input_findings"] == 1
    assert summary["total_report_entries"] == 1
    assert summary["coverage"]["is_complete"]
    assert summary["entries_by_status"]["error"] == 1
