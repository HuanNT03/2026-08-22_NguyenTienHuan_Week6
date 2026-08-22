"""Unit and integration tests for ReAct Execution Engine."""

import json
from unittest.mock import MagicMock, patch

from openai import OpenAI

from src.agent.analyzer import analyze_group
from src.agent.config import AgentConfig
from src.agent.models import AnalysisGroup, ReportEntry
from src.agent.react_engine import ReActAnalysisEngine
from src.agent.tools import ToolDispatcher
from src.retrieval.service import KnowledgeSearchService


def make_mock_choice(content: str | None = None, tool_calls: list | None = None) -> MagicMock:
    """Helper to construct mock OpenAI ChatCompletion response choice."""
    mock_msg = MagicMock()
    mock_msg.content = content
    mock_msg.tool_calls = tool_calls or []
    mock_choice = MagicMock()
    mock_choice.message = mock_msg
    mock_resp = MagicMock()
    mock_resp.choices = [mock_choice]
    return mock_resp


def make_mock_tool_call(call_id: str, name: str, args_dict: dict) -> MagicMock:
    """Helper to construct mock ToolCall object."""
    tc = MagicMock()
    tc.id = call_id
    tc.function.name = name
    tc.function.arguments = json.dumps(args_dict)
    return tc


def test_react_engine_multi_turn_tool_calling_success() -> None:
    """Verify ReAct engine runs multi-turn loop: Thought -> Tool Call -> Observation -> Final JSON."""
    mock_group = AnalysisGroup(
        group_id="grp_cwe89_001",
        primary_cwe="CWE-89",
        correlation_type="sast_dast_suspected",
        correlated_fingerprints=["fp_sha256:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        findings=[
            {
                "fingerprint": "fp_sha256:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "finding_id": "fnd_11111111111111111111111111111111",
                "tool": {"name": "semgrep", "scan_type": "SAST"},
                "title": "SQL Injection in search",
                "severity": "high",
                "cwe_ids": ["CWE-89"],
                "location": {"kind": "code", "path": "routes/search.ts", "start_line": 20},
            }
        ],
    )

    mock_client = MagicMock(spec=OpenAI)

    # Turn 1: Model calls search_knowledge_base
    tc1 = make_mock_tool_call("call_1", "search_knowledge_base", {"query": "CWE-89 SQL Injection"})
    resp_turn1 = make_mock_choice(content="Tôi cần tra cứu tri thức về CWE-89.", tool_calls=[tc1])

    # Turn 2: Model returns final JSON report
    valid_final_json = json.dumps(
        {
            "entries": [
                {
                    "analysis_id": "analysis_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "analysis_group_id": "grp_cwe89_001",
                    "fingerprint": "fp_sha256:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "finding_id": "fnd_11111111111111111111111111111111",
                    "tool": "semgrep",
                    "scan_type": "SAST",
                    "title": "Lỗ hổng SQL Injection tại search",
                    "primary_cwe_id": "CWE-89",
                    "location_summary": "routes/search.ts dòng 20",
                    "severity": {
                        "agent_assessment": "high",
                        "original_scanner": "high",
                        "rationale": "Lỗ hổng nghiêm trọng",
                    },
                    "confidence": {
                        "level": "confirmed",
                        "rationale": "Xác nhận qua tra cứu tri thức và luồng dữ liệu",
                    },
                    "correlation_type": "sast_dast_confirmed",
                    "evidence_summary": "Tìm thấy chuỗi nối trực tiếp vào SQL query",
                    "explanation": "Câu truy vấn SQL không sử dụng tham số hóa",
                    "recommended_action": "Sử dụng Parameterized Query",
                }
            ]
        }
    )
    resp_turn2 = make_mock_choice(content=valid_final_json, tool_calls=[])

    mock_client.chat.completions.create.side_effect = [resp_turn1, resp_turn2]

    mock_kb = MagicMock(spec=KnowledgeSearchService)
    mock_kb.search.return_value = []
    dispatcher = ToolDispatcher(kb_service=mock_kb)

    engine = ReActAnalysisEngine(client=mock_client, config=AgentConfig(), dispatcher=dispatcher)
    entries = engine.run_group_analysis(mock_group, system_prompt="System Prompt")

    assert len(entries) == 1
    assert isinstance(entries[0], ReportEntry)
    assert entries[0].confidence.level == "confirmed"
    assert entries[0].correlation_type == "sast_dast_confirmed"
    assert mock_client.chat.completions.create.call_count == 2


def test_react_engine_direct_answer_turn1() -> None:
    """Verify ReAct engine accepts immediate final answer without tool calls."""
    mock_group = AnalysisGroup(
        group_id="grp_cwe200_001",
        primary_cwe="CWE-200",
        correlation_type="sast_only",
        correlated_fingerprints=["fp_sha256:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
        findings=[
            {
                "fingerprint": "fp_sha256:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "finding_id": "fnd_22222222222222222222222222222222",
                "tool": {"name": "semgrep", "scan_type": "SAST"},
                "title": "Information Exposure",
                "severity": "medium",
                "cwe_ids": ["CWE-200"],
                "location": {"kind": "code", "path": "util/logger.ts", "start_line": 10},
            }
        ],
    )

    mock_client = MagicMock(spec=OpenAI)
    final_json = json.dumps(
        {
            "entries": [
                {
                    "analysis_id": "analysis_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "fingerprint": "fp_sha256:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "finding_id": "fnd_22222222222222222222222222222222",
                    "tool": "semgrep",
                    "scan_type": "SAST",
                    "title": "Lỗ hổng lộ lọt thông tin",
                    "primary_cwe_id": "CWE-200",
                    "location_summary": "util/logger.ts dòng 10",
                    "severity": {"agent_assessment": "medium", "rationale": "Lộ log"},
                    "confidence": {"level": "medium", "rationale": "Phân tích mã nguồn"},
                    "correlation_type": "sast_only",
                    "evidence_summary": "Log dữ liệu",
                    "explanation": "Ghi log chưa che dữ liệu",
                    "recommended_action": "Sử dụng redactor",
                }
            ]
        }
    )
    mock_client.chat.completions.create.return_value = make_mock_choice(content=final_json)

    dispatcher = ToolDispatcher()
    engine = ReActAnalysisEngine(client=mock_client, config=AgentConfig(), dispatcher=dispatcher)
    entries = engine.run_group_analysis(mock_group, system_prompt="System Prompt")

    assert len(entries) == 1
    assert entries[0].confidence.level == "medium"
    assert mock_client.chat.completions.create.call_count == 1


def test_react_engine_max_steps_fallback_coverage() -> None:
    """Verify ReAct engine guarantees 100% coverage fallback when LLM encounters continuous errors."""
    mock_group = AnalysisGroup(
        group_id="grp_err_001",
        primary_cwe="CWE-79",
        correlation_type="dast_only",
        correlated_fingerprints=["fp_sha256:v1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],
        findings=[
            {
                "fingerprint": "fp_sha256:v1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "finding_id": "fnd_33333333333333333333333333333333",
                "tool": {"name": "zap", "scan_type": "DAST"},
                "title": "XSS in search",
                "severity": "high",
                "cwe_ids": ["CWE-79"],
                "location": {"kind": "http", "endpoint": "/#/search", "parameter": "q"},
            }
        ],
    )

    mock_client = MagicMock(spec=OpenAI)
    # Simulate repeated API error
    mock_client.chat.completions.create.side_effect = RuntimeError("OpenAI API Connection Timeout")

    dispatcher = ToolDispatcher()
    engine = ReActAnalysisEngine(client=mock_client, config=AgentConfig(), dispatcher=dispatcher)
    entries = engine.run_group_analysis(mock_group, system_prompt="System Prompt")

    assert len(entries) == 1
    assert entries[0].analysis_status == "error"
    assert entries[0].fingerprint == "fp_sha256:v1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    assert "Connection Timeout" in entries[0].explanation


def test_analyze_group_routes_to_react_by_default() -> None:
    """Verify analyze_group executes via ReAct engine when agent_mode='react'."""
    mock_group = AnalysisGroup(
        group_id="grp_route_001",
        primary_cwe="CWE-89",
        correlation_type="sast_only",
        correlated_fingerprints=["fp_sha256:v1:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],
        findings=[
            {
                "fingerprint": "fp_sha256:v1:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "finding_id": "fnd_44444444444444444444444444444444",
                "tool": {"name": "semgrep", "scan_type": "SAST"},
                "title": "SQL Injection",
                "severity": "high",
                "cwe_ids": ["CWE-89"],
                "location": {"kind": "code", "path": "routes/login.ts", "start_line": 15},
            }
        ],
    )

    cfg = AgentConfig()
    cfg.agent_mode = "react"

    with patch("src.agent.analyzer.ReActAnalysisEngine") as mock_engine_cls:
        mock_instance = MagicMock()
        mock_instance.run_group_analysis.return_value = [
            ReportEntry(
                analysis_id="analysis_dddddddddddddddddddddddddddddddd",
                analysis_group_id="grp_route_001",
                fingerprint="fp_sha256:v1:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                finding_id="fnd_44444444444444444444444444444444",
                tool="semgrep",
                scan_type="SAST",
                title="Lỗ hổng SQL Injection",
                primary_cwe_id="CWE-89",
                location_summary="routes/login.ts dòng 15",
                severity={"agent_assessment": "high", "rationale": "Nghiêm trọng"},
                confidence={"level": "high", "rationale": "ReAct verified"},
                correlation_type="sast_only",
                evidence_summary="Tương quan",
                explanation="Giải thích",
                recommended_action="Khắc phục",
                metadata={
                    "analyzed_at": "2026-08-22T00:00:00Z",
                    "model": "qwen",
                    "prompt_version": "v2",
                    "grouping_source": "hybrid",
                },
            )
        ]
        mock_engine_cls.return_value = mock_instance

        mock_kb = MagicMock(spec=KnowledgeSearchService)
        entries = analyze_group(mock_group, kb_service=mock_kb, config=cfg)

        assert len(entries) == 1
        mock_instance.run_group_analysis.assert_called_once()
