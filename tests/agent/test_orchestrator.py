"""Unit tests for src/agent/orchestrator.py."""

import json
from pathlib import Path
from unittest.mock import MagicMock

from src.agent.config import AgentConfig
from src.agent.orchestrator import run_analysis, verify_coverage


def test_verify_coverage_detects_complete_and_missing() -> None:
    findings = [
        {"fingerprint": "fp1", "finding_id": "fnd1"},
        {"fingerprint": "fp2", "finding_id": "fnd2"},
    ]

    mock_entry_1 = MagicMock()
    mock_entry_1.fingerprint = "fp1"
    mock_entry_2 = MagicMock()
    mock_entry_2.fingerprint = "fp2"

    res_complete = verify_coverage(findings, [mock_entry_1, mock_entry_2])
    assert res_complete["is_complete"]
    assert res_complete["total_input"] == 2
    assert res_complete["total_covered"] == 2
    assert len(res_complete["missing_fingerprints"]) == 0

    res_incomplete = verify_coverage(findings, [mock_entry_1])
    assert not res_incomplete["is_complete"]
    assert res_incomplete["total_covered"] == 1
    assert "fp2" in res_incomplete["missing_fingerprints"]


def test_run_analysis_with_mock_client(tmp_path: Path) -> None:
    # Prepare dummy findings file
    findings_file = tmp_path / "unified-findings.jsonl"
    dummy_finding = {
        "schema_version": "2.0.0",
        "finding_id": "fnd_0123456789abcdef0123456789abcdef",
        "fingerprint": f"fp_sha256:v1:{'a' * 64}",
        "group_key": f"grp_sha256:v1:{'b' * 64}",
        "tool": {"name": "semgrep", "scan_type": "SAST"},
        "title": "SQL Injection",
        "cwe_ids": ["CWE-89"],
        "location": {"kind": "code", "path": "routes/login.ts", "start_line": 34},
        "evidence": {"kind": "code"},
    }
    findings_file.write_text(json.dumps(dummy_finding) + "\n", encoding="utf-8")

    out_dir = tmp_path / "analyzed"
    config = AgentConfig(api_key="mock_key", output_dir=out_dir)

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                content=json.dumps(
                    {
                        "entries": [
                            {
                                "schema_version": "1.0.0",
                                "analysis_id": "analysis_0123456789abcdef0123456789abcdef",
                                "analysis_group_id": "grp_sqli_001",
                                "analysis_status": "success",
                                "fingerprint": f"fp_sha256:v1:{'a' * 64}",
                                "finding_id": "fnd_0123456789abcdef0123456789abcdef",
                                "tool": "semgrep",
                                "scan_type": "SAST",
                                "title": "SQL Injection",
                                "primary_cwe_id": "CWE-89",
                                "all_cwe_ids": ["CWE-89"],
                                "owasp_category": "OWASP-A03:2021",
                                "location_summary": "routes/login.ts dòng 34",
                                "severity": {
                                    "agent_assessment": "critical",
                                    "original_scanner": "critical",
                                    "rationale": "High risk",
                                },
                                "confidence": {
                                    "level": "high",
                                    "rationale": "Direct evidence",
                                },
                                "correlation_type": "sast_only",
                                "correlated_with": [],
                                "evidence_summary": "Summary",
                                "explanation": "Explanation",
                                "recommended_action": "Fix action",
                                "proposed_test_request": None,
                                "knowledge_references": [],
                                "metadata": {
                                    "analyzed_at": "2026-08-07T10:00:00Z",
                                    "model": "qwen-plus",
                                    "prompt_version": "system_v1",
                                    "grouping_source": "cwe_title_hybrid",
                                    "retry_count": 0,
                                },
                            }
                        ]
                    }
                )
            )
        )
    ]
    mock_client.chat.completions.create.return_value = mock_response

    mock_kb = MagicMock()
    mock_kb.search.return_value = []

    summary = run_analysis(
        findings_path=findings_file,
        config=config,
        client=mock_client,
        kb_service=mock_kb,
    )

    assert summary["total_input_findings"] == 1
    assert summary["total_report_entries"] == 1
    assert summary["coverage"]["is_complete"]

    # Check generated output files
    output_report = Path(summary["report_file"])
    assert output_report.is_file()
    lines = output_report.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry_dict = json.loads(lines[0])
    assert entry_dict["fingerprint"] == f"fp_sha256:v1:{'a' * 64}"
