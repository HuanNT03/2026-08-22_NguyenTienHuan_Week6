"""Contract test for security_analysis_report.schema.json."""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
REPORT_SCHEMA_PATH = ROOT / "schemas/security_analysis_report.schema.json"


def _valid_report_entry() -> dict[str, Any]:
    return {
        "schema_version": "1.1.0",
        "analysis_id": "analysis_0123456789abcdef0123456789abcdef",
        "analysis_group_id": "grp_sqli_login",
        "analysis_status": "success",
        "fingerprint": f"fp_sha256:v1:{'a' * 64}",
        "finding_id": "fnd_0123456789abcdef0123456789abcdef",
        "tool": "semgrep",
        "scan_type": "SAST",
        "title": "SQL Injection tại Chức năng Đăng nhập (Login)",
        "primary_cwe_id": "CWE-89",
        "all_cwe_ids": ["CWE-89"],
        "owasp_category": "OWASP-A03:2021",
        "location_summary": "routes/login.ts dòng 34",
        "severity": {
            "agent_assessment": "critical",
            "original_scanner": "critical",
            "rationale": "Chuỗi SQL được nối trực tiếp từ input mà không dùng parameterized query.",
        },
        "confidence": {
            "level": "confirmed",
            "rationale": "Xác nhận bởi cả SAST (Semgrep) và DAST (ZAP).",
        },
        "correlation_type": "sast_dast_suspected",
        "correlated_with": [f"fp_sha256:v1:{'b' * 64}"],
        "evidence_summary": "Semgrep phát hiện data flow từ req.body -> SQL string concatenation.",
        "explanation": "Lỗ hổng xảy ra do dữ liệu không được sanitize trước khi truy vấn.",
        "recommended_action": "Sử dụng Parameterized Queries hoặc ORM.",
        "proposed_test_request": {
            "method": "POST",
            "endpoint": "/rest/user/login",
            "headers": {"Content-Type": "application/json"},
            "payload": {"email": "admin' --", "password": "123"},
            "rationale": "Kiểm tra SQL Injection bằng payload bypass auth.",
            "status": "not_sent",
        },
        "knowledge_references": [
            {
                "doc_id": "cwe_89",
                "title": "CWE-89: SQL Injection",
                "relevance": "Mô tả chi tiết lỗ hổng và giải pháp",
            }
        ],
        "metadata": {
            "analyzed_at": "2026-08-07T10:00:00Z",
            "model": "qwen-plus",
            "prompt_version": "system_v1",
            "grouping_source": "cwe_title_hybrid",
            "retry_count": 0,
        },
    }


def _valid_summary_metadata() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "analyzed_at": "2026-08-22T10:00:00Z",
        "input_file": "reports/normalized/unified-findings-test.jsonl",
        "report_file": "reports/analyzed/security-analysis-report-test.jsonl",
        "log_file": "logs/agent-runner.log",
        "total_input_findings": 5,
        "total_report_entries": 5,
        "total_analysis_groups": 2,
        "coverage": {
            "is_complete": True,
            "total_expected": 5,
            "total_analyzed": 5,
            "missing_fingerprints": [],
        },
        "entries_by_status": {"success": 5},
        "entries_by_correlation_type": {"sast_only": 3, "sast_dast_confirmed": 2},
        "token_usage": {
            "prompt_tokens": 1250,
            "completion_tokens": 450,
            "total_tokens": 1700,
        },
        "execution_time_seconds": 3.45,
        "config": {
            "agent_mode": "react",
            "model": "qwen-plus",
            "base_url": None,
            "temperature": 0.2,
            "max_retries": 3,
            "max_react_steps": 5,
            "prompt_version": "system_v2",
        },
    }


def _get_validator() -> Draft202012Validator:
    schema = json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _get_summary_validator() -> Draft202012Validator:
    summary_schema_path = ROOT / "schemas/agent_runner_summary.schema.json"
    schema = json.loads(summary_schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_valid_report_entry_passes_schema() -> None:
    validator = _get_validator()
    entry = _valid_report_entry()
    errors = list(validator.iter_errors(entry))
    assert errors == []


@pytest.mark.parametrize(
    "status_val",
    ["not_sent", "sent", "rejected", "timeout_rejected"],
)
def test_proposed_test_request_status_enums(status_val: str) -> None:
    validator = _get_validator()
    entry = _valid_report_entry()
    assert entry["proposed_test_request"] is not None
    entry["proposed_test_request"]["status"] = status_val
    errors = list(validator.iter_errors(entry))
    assert errors == []


def test_proposed_test_request_invalid_status_rejected() -> None:
    validator = _get_validator()
    entry = _valid_report_entry()
    assert entry["proposed_test_request"] is not None
    entry["proposed_test_request"]["status"] = "unknown_status"
    errors = list(validator.iter_errors(entry))
    assert len(errors) > 0


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("schema_version", "2.0.0"),
        ("analysis_id", "invalid_id"),
        ("analysis_group_id", ""),
        ("analysis_status", "unknown_status"),
        ("fingerprint", "invalid_fp"),
        ("finding_id", "invalid_fnd"),
        ("tool", "invalid_tool"),
        ("scan_type", "INVALID"),
        ("primary_cwe_id", "CWE-ABC"),
        ("owasp_category", "OWASP-INVALID"),
        ("correlation_type", "invalid_correlation"),
    ],
)
def test_invalid_report_entry_fields_rejected(field: str, invalid_value: Any) -> None:
    validator = _get_validator()
    entry = _valid_report_entry()
    entry[field] = invalid_value
    errors = list(validator.iter_errors(entry))
    assert len(errors) > 0, f"Expected validation error for {field}={invalid_value!r}"


def test_nullable_proposed_test_request() -> None:
    validator = _get_validator()
    entry = _valid_report_entry()
    entry["proposed_test_request"] = None
    assert list(validator.iter_errors(entry)) == []


def test_metadata_prompt_injection_detected_field() -> None:
    validator = _get_validator()
    entry = _valid_report_entry()
    entry["metadata"]["prompt_injection_detected"] = True
    assert list(validator.iter_errors(entry)) == []

    entry["metadata"]["prompt_injection_detected"] = "not_a_bool"
    assert len(list(validator.iter_errors(entry))) > 0


def test_agent_runner_summary_schema_valid() -> None:
    validator = _get_summary_validator()
    summary = _valid_summary_metadata()
    errors = list(validator.iter_errors(summary))
    assert errors == []


def test_agent_runner_summary_schema_missing_tokens_rejected() -> None:
    validator = _get_summary_validator()
    summary = _valid_summary_metadata()
    del summary["token_usage"]
    errors = list(validator.iter_errors(summary))
    assert len(errors) > 0


def _valid_trace_entry(run_type: str = "llm") -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "trace_id": f"trc_{'a' * 32}",
        "run_id": f"run_{'b' * 32}",
        "parent_run_id": f"run_{'c' * 32}",
        "group_id": "grp_sqli_login",
        "step_index": 1,
        "run_type": run_type,
        "name": "qwen-plus",
        "start_time": "2026-08-22T10:00:00Z",
        "end_time": "2026-08-22T10:00:02Z",
        "duration_ms": 2150.5,
        "status": "success",
        "inputs": {
            "messages": [
                {"role": "system", "content": "You are Sentinel Security Agent."},
                {"role": "user", "content": "Analyze SQL Injection group."},
            ]
        },
        "outputs": {
            "thought": "Cần tra cứu tri thức bảo mật về CWE-89 và kiểm tra route /rest/user/login.",
            "tool_calls": [
                {
                    "name": "search_knowledge_base",
                    "arguments": {"query": "CWE-89 SQL Injection", "mode": "hybrid"},
                }
            ],
        },
        "token_usage": {
            "prompt_tokens": 1250,
            "completion_tokens": 120,
            "total_tokens": 1370,
        },
        "error": None,
        "metadata": {
            "model": "qwen-plus",
            "agent_mode": "react",
            "prompt_version": "system_v2",
            "temperature": 0.2,
            "max_steps": 5,
            "tags": ["sqli", "react_loop"],
        },
    }


def _get_trace_log_validator() -> Draft202012Validator:
    log_schema_path = ROOT / "schemas/agent_runner_log.schema.json"
    schema = json.loads(log_schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@pytest.mark.parametrize(
    "run_type",
    ["chain", "llm", "tool", "retriever", "guardrail", "hitl"],
)
def test_agent_runner_log_schema_valid_spans(run_type: str) -> None:
    validator = _get_trace_log_validator()
    trace = _valid_trace_entry(run_type=run_type)
    errors = list(validator.iter_errors(trace))
    assert errors == []


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("schema_version", "2.0.0"),
        ("trace_id", "invalid_trace"),
        ("run_id", "invalid_run"),
        ("group_id", "invalid-group"),
        ("run_type", "unsupported_type"),
        ("status", "unknown_status"),
        ("duration_ms", -10),
    ],
)
def test_agent_runner_log_schema_invalid_fields_rejected(field: str, invalid_value: Any) -> None:
    validator = _get_trace_log_validator()
    trace = _valid_trace_entry()
    trace[field] = invalid_value
    errors = list(validator.iter_errors(trace))
    assert len(errors) > 0
