"""Unit tests for src/agent/prompt_builder.py."""

from src.agent.models import AnalysisGroup
from src.agent.prompt_builder import build_user_prompt, compress_finding


def test_compress_finding_strips_only_pipeline_metadata() -> None:
    finding = {
        "schema_version": "2.0.0",
        "finding_id": "fnd_1234567890abcdef1234567890abcdef",
        "fingerprint": f"fp_sha256:v1:{'a' * 64}",
        "group_key": f"grp_sha256:v1:{'b' * 64}",
        "tool": {"name": "semgrep", "version": "1.171.0", "scan_type": "SAST"},
        "scan": {"run_id": "semgrep_123", "pipeline_run_id": None, "scanned_at": "2026-08-06T00:00:00Z"},
        "target": {"name": "juice-shop", "version": "20.1.1", "commit_sha": None, "base_url": None},
        "rule": {
            "id": "sql-injection-rule",
            "reference_id": None,
            "name": None,
            "native_severity": "CRITICAL",
            "native_confidence": "MEDIUM",
        },
        "normalization": {"normalizer_version": "2.0.0", "normalized_at": "2026-08-06T00:00:00Z"},
        "title": "SQL Injection",
        "description": "User input concatenated into SQL query",
        "categories": ["security"],
        "severity": "critical",
        "confidence": "medium",
        "cwe_ids": ["CWE-89"],
        "owasp_categories": ["OWASP-A03:2021"],
        "wasc_ids": [],
        "location": {
            "kind": "code",
            "path": "routes/login.ts",
            "start_line": 34,
            "start_column": 5,
            "end_line": 34,
            "end_column": 40,
        },
        "evidence": {
            "kind": "code",
            "code_evidence": {
                "code_snippet": {
                    "content": "SELECT * FROM Users WHERE email = " + "'" + "req.body.email" + "'",
                    "context_before": [],
                    "context_after": [],
                },
                "matched_contents": [],
                "related_context": [],
                "redacted": False,
                "truncated": False,
            },
            "http_evidence": None,
            "quality": "direct",
            "provenance": "semgrep.json:results[0]",
        },
        "data_flow": [
            {
                "kind": "taint",
                "engine": "semgrep",
                "source": {
                    "step_index": 0,
                    "path": "routes/login.ts",
                    "line": 34,
                    "column": 5,
                    "content": "req.body.email",
                    "message": None,
                },
                "steps": [],
                "sink": {
                    "step_index": 1,
                    "path": "routes/login.ts",
                    "line": 34,
                    "column": 30,
                    "content": "SELECT",
                    "message": None,
                },
            }
        ],
        "solution": None,
        "references": ["https://owasp.org"],
        "raw_sources": [
            {"format": "semgrep-json", "report_path": "reports/raw/semgrep.json", "json_pointer": "/results/0"}
        ],
    }

    compressed = compress_finding(finding)

    # Verify pipeline metadata stripped
    assert "schema_version" not in compressed
    assert "normalization" not in compressed
    assert "scan" not in compressed

    # Verify vulnerability context preserved
    assert compressed["finding_id"] == finding["finding_id"]
    assert compressed["fingerprint"] == finding["fingerprint"]
    assert compressed["group_key"] == finding["group_key"]
    assert compressed["cwe_ids"] == ["CWE-89"]
    assert compressed["evidence"]["code_evidence"]["code_snippet"]["content"] is not None
    assert len(compressed["data_flow"]) == 1


def test_build_user_prompt_redacts_sensitive_info() -> None:
    group = AnalysisGroup(
        group_id="grp_test_001",
        primary_cwe="CWE-89",
        findings=[
            {
                "finding_id": "fnd_1234567890abcdef1234567890abcdef",
                "fingerprint": f"fp_sha256:v1:{'a' * 64}",
                "tool": {"name": "zap", "scan_type": "DAST"},
                "title": "SQL Injection",
                "cwe_ids": ["CWE-89"],
                "location": {"kind": "http", "endpoint": "/rest/user/login", "parameter": "email"},
                "evidence": {"http_evidence": {"request_excerpt": "POST /login email=test@secret.com&pass=123"}},
            }
        ],
        correlation_type="dast_only",
        correlated_fingerprints=[f"fp_sha256:v1:{'a' * 64}"],
    )

    kb_snippets = [{"doc_id": "cwe_89", "title": "CWE-89: SQL Injection", "summary": "SQL Injection summary"}]

    prompt = build_user_prompt(group, kb_snippets)

    assert "grp_test_001" in prompt
    assert "CWE-89" in prompt
    assert "test@secret.com" not in prompt
    assert "[REDACTED_EMAIL]" in prompt
