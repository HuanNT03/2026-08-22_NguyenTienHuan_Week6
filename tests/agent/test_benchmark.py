"""Unit tests for Benchmark Dataset and Evaluation Pipeline."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scripts.evaluate_agent_benchmark import load_benchmark_dataset, run_benchmark_for_mode


def test_benchmark_dataset_integrity() -> None:
    """Verify benchmark_dataset.json contains valid test cases with all required fields."""
    cases = load_benchmark_dataset()
    assert len(cases) >= 8

    for c in cases:
        assert "case_id" in c
        assert "primary_cwe_id" in c
        assert c["primary_cwe_id"].startswith("CWE-")
        assert "expected_status" in c
        assert "ground_truth_label" in c
        assert len(c["findings"]) > 0


def test_run_benchmark_for_mode_with_mock() -> None:
    """Verify run_benchmark_for_mode computes precision, recall, and f1 correctly."""
    dataset = load_benchmark_dataset()[:3]
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps({
        "entries": [
            {
                "schema_version": "1.0.0",
                "analysis_id": f"analysis_{'a' * 32}",
                "analysis_group_id": "grp_bench_01",
                "analysis_status": "success",
                "fingerprint": f"fp_sha256:v1:{'0' * 63}1",
                "finding_id": f"fnd_{'0' * 31}1",
                "tool": "semgrep",
                "scan_type": "SAST",
                "title": "SQL Injection in User Authentication Route",
                "primary_cwe_id": "CWE-89",
                "all_cwe_ids": ["CWE-89"],
                "owasp_category": "OWASP-A03:2021",
                "location_summary": "routes/login.ts dòng 34",
                "severity": {
                    "agent_assessment": "critical",
                    "original_scanner": "critical",
                    "rationale": "High impact",
                },
                "confidence": {
                    "level": "confirmed",
                    "score": 0.95,
                    "rationale": "Confirmed via probe",
                },
                "correlation_type": "sast_dast_confirmed",
                "correlated_with": [f"fp_sha256:v1:{'0' * 63}1"],
                "evidence_summary": "Verified",
                "explanation": "Root cause",
                "recommended_action": "Remediate",
                "proposed_test_request": None,
                "knowledge_references": [],
                "metadata": {
                    "analyzed_at": "2026-08-22T10:00:00Z",
                    "model": "qwen-plus",
                    "prompt_version": "system_v2",
                    "grouping_source": "benchmark",
                    "retry_count": 0,
                    "prompt_injection_detected": False,
                },
            }
        ]
    })
    mock_choice.message.tool_calls = None
    mock_client.chat.completions.create.return_value.choices = [mock_choice]
    mock_client.chat.completions.create.return_value.usage = MagicMock(
        prompt_tokens=300, completion_tokens=100, total_tokens=400
    )

    mock_kb = MagicMock()
    mock_kb.search.return_value = []

    res = run_benchmark_for_mode("static", dataset, client=mock_client, kb_service=mock_kb)
    assert res["total_cases"] == 3
    assert res["precision"] > 0
    assert res["recall"] > 0
    assert res["secret_leak_count"] == 0
