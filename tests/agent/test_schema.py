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


def _get_validator() -> Draft202012Validator:
    schema = json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_valid_report_entry_passes_schema() -> None:
    validator = _get_validator()
    entry = _valid_report_entry()
    errors = list(validator.iter_errors(entry))
    assert errors == []


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
