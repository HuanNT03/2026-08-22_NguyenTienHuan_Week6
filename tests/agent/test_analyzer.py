"""Unit tests for src/agent/analyzer.py with mocked LLM calls."""

import json
from unittest.mock import MagicMock

from src.agent.analyzer import analyze_group
from src.agent.config import AgentConfig
from src.agent.models import AnalysisGroup


def _sample_group() -> AnalysisGroup:
    return AnalysisGroup(
        group_id="grp_sqli_001",
        primary_cwe="CWE-89",
        findings=[
            {
                "finding_id": "fnd_0123456789abcdef0123456789abcdef",
                "fingerprint": f"fp_sha256:v1:{'a' * 64}",
                "tool": {"name": "semgrep", "scan_type": "SAST"},
                "title": "SQL Injection",
                "severity": "critical",
                "confidence": "high",
                "cwe_ids": ["CWE-89"],
                "location": {"kind": "code", "path": "routes/login.ts", "start_line": 34},
                "evidence": {"kind": "code"},
            }
        ],
        correlation_type="sast_only",
        correlated_fingerprints=[f"fp_sha256:v1:{'a' * 64}"],
    )


def test_analyze_group_success_with_mock_client() -> None:
    config = AgentConfig(api_key="mock_key")
    group = _sample_group()

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
                                "title": "SQL Injection tại Chức năng Đăng nhập",
                                "primary_cwe_id": "CWE-89",
                                "all_cwe_ids": ["CWE-89"],
                                "owasp_category": "OWASP-A03:2021",
                                "location_summary": "routes/login.ts dòng 34",
                                "severity": {
                                    "agent_assessment": "critical",
                                    "original_scanner": "critical",
                                    "rationale": "Chuỗi SQL được nối trực tiếp từ input.",
                                },
                                "confidence": {
                                    "level": "high",
                                    "rationale": "Semgrep phát hiện taint flow rõ ràng.",
                                },
                                "correlation_type": "sast_only",
                                "correlated_with": [f"fp_sha256:v1:{'a' * 64}"],
                                "evidence_summary": "Taint flow từ req.body.email vào SQL query.",
                                "explanation": "Lỗ hổng xảy ra do không dùng Parameterized Query.",
                                "recommended_action": "Sử dụng Parameterized Query.",
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

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_response

    mock_kb = MagicMock()
    mock_kb.search.return_value = []

    entries = analyze_group(group, kb_service=mock_kb, client=mock_client, config=config)
    assert len(entries) == 1
    assert entries[0].fingerprint == f"fp_sha256:v1:{'a' * 64}"
    assert entries[0].analysis_status == "success"


def test_analyze_group_fallback_on_repeated_failure() -> None:
    config = AgentConfig(api_key="mock_key", max_retries=1)
    group = _sample_group()

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception("LLM Provider API Error")

    mock_kb = MagicMock()
    mock_kb.search.return_value = []

    entries = analyze_group(group, kb_service=mock_kb, client=mock_client, config=config)

    # Must return error entry to guarantee 100% coverage
    assert len(entries) == 1
    assert entries[0].fingerprint == f"fp_sha256:v1:{'a' * 64}"
    assert entries[0].analysis_status == "error"
    assert "LLM Provider API Error" in entries[0].explanation
