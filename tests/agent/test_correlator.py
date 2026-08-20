"""Unit tests for src/agent/correlator.py."""

from src.agent.correlator import (
    correlate_findings,
    extract_keywords,
    match_param_to_dataflow,
    titles_are_similar,
)


def test_extract_keywords() -> None:
    kw = extract_keywords("SQL Injection in Node.js")
    assert "sql" in kw
    assert "injection" in kw
    assert "nodejs" in kw or "node" in kw


def test_titles_are_similar() -> None:
    assert titles_are_similar("SQL Injection", "Database query built from user-controlled sources")
    assert titles_are_similar("Open Redirect", "External Redirect")
    assert not titles_are_similar("Private IP Disclosure", "Information exposure through stack trace")
    assert not titles_are_similar("SQL Injection", "Cross-site Scripting")
    assert not titles_are_similar(None, "SQL Injection")


def test_match_param_to_dataflow() -> None:
    data_flow = [
        {
            "source": {"content": "req.body.email"},
            "steps": [{"content": "email"}],
            "sink": {"content": "SELECT * FROM users WHERE email = "},
        }
    ]
    assert match_param_to_dataflow("email", data_flow)
    assert not match_param_to_dataflow("password", data_flow)
    assert not match_param_to_dataflow(None, data_flow)
    assert not match_param_to_dataflow("email", None)


def test_correlate_findings_sql_injection() -> None:
    sast_finding = {
        "finding_id": "fnd_sast_1",
        "fingerprint": f"fp_sha256:v1:{'1' * 64}",
        "tool": {"name": "semgrep", "scan_type": "SAST"},
        "title": "SQL Injection",
        "cwe_ids": ["CWE-89"],
        "location": {"kind": "code", "path": "routes/login.ts", "start_line": 34},
        "data_flow": [{"source": {"content": "req.body.email"}, "steps": [], "sink": {"content": "SELECT"}}],
    }
    dast_finding = {
        "finding_id": "fnd_dast_1",
        "fingerprint": f"fp_sha256:v1:{'2' * 64}",
        "tool": {"name": "zap", "scan_type": "DAST"},
        "title": "SQL Injection",
        "cwe_ids": ["CWE-89"],
        "location": {"kind": "http", "endpoint": "/rest/user/login", "parameter": "email"},
    }

    result = correlate_findings(sast_finding, dast_finding)
    assert result.is_correlated
    assert "CWE-89" in result.cwe_overlap
    assert result.is_title_similar
    assert result.confidence in ("medium", "high")


def test_correlate_findings_broad_cwe_prevented() -> None:
    sast_finding = {
        "finding_id": "fnd_sast_2",
        "fingerprint": f"fp_sha256:v1:{'3' * 64}",
        "tool": {"name": "codeql", "scan_type": "SAST"},
        "title": "Uncontrolled resource consumption",
        "cwe_ids": ["CWE-400"],
        "location": {"kind": "code", "path": "server.ts", "start_line": 270},
    }
    sast_finding_other_file = {
        "finding_id": "fnd_sast_3",
        "fingerprint": f"fp_sha256:v1:{'4' * 64}",
        "tool": {"name": "codeql", "scan_type": "SAST"},
        "title": "Privilege escalation",
        "cwe_ids": ["CWE-400"],
        "location": {"kind": "code", "path": "routes/currentUser.ts", "start_line": 31},
    }

    result = correlate_findings(sast_finding, sast_finding_other_file)
    assert not result.is_correlated
    assert result.confidence == "none"
