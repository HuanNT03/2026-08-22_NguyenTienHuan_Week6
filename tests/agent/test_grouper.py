"""Unit tests for src/agent/grouper.py."""

from src.agent.grouper import build_analysis_groups


def _sample_findings() -> list[dict]:
    return [
        {
            "schema_version": "2.0.0",
            "finding_id": "fnd_00000000000000000000000000000001",
            "fingerprint": f"fp_sha256:v1:{'1' * 64}",
            "group_key": f"grp_sha256:v1:{'a' * 64}",
            "tool": {"name": "semgrep", "scan_type": "SAST"},
            "title": "SQL Injection",
            "cwe_ids": ["CWE-89"],
            "location": {"kind": "code", "path": "routes/login.ts", "start_line": 34},
            "evidence": {"kind": "code"},
        },
        {
            "schema_version": "2.0.0",
            "finding_id": "fnd_00000000000000000000000000000002",
            "fingerprint": f"fp_sha256:v1:{'2' * 64}",
            "group_key": f"grp_sha256:v1:{'b' * 64}",
            "tool": {"name": "codeql", "scan_type": "SAST"},
            "title": "Database query built from user-controlled sources",
            "cwe_ids": ["CWE-89", "CWE-90", "CWE-943"],
            "location": {"kind": "code", "path": "routes/login.ts", "start_line": 34},
            "evidence": {"kind": "code"},
        },
        {
            "schema_version": "2.0.0",
            "finding_id": "fnd_00000000000000000000000000000003",
            "fingerprint": f"fp_sha256:v1:{'3' * 64}",
            "group_key": f"grp_sha256:v1:{'c' * 64}",
            "tool": {"name": "zap", "scan_type": "DAST"},
            "title": "SQL Injection",
            "cwe_ids": ["CWE-89"],
            "location": {"kind": "http", "endpoint": "/rest/user/login", "parameter": "email"},
            "evidence": {"kind": "http"},
        },
        {
            "schema_version": "2.0.0",
            "finding_id": "fnd_00000000000000000000000000000004",
            "fingerprint": f"fp_sha256:v1:{'4' * 64}",
            "group_key": f"grp_sha256:v1:{'d' * 64}",
            "tool": {"name": "codeql", "scan_type": "SAST"},
            "title": "Rate limit check",
            "cwe_ids": ["CWE-400"],
            "location": {"kind": "code", "path": "server.ts", "start_line": 270},
            "evidence": {"kind": "code"},
        },
        {
            "schema_version": "2.0.0",
            "finding_id": "fnd_00000000000000000000000000000005",
            "fingerprint": f"fp_sha256:v1:{'5' * 64}",
            "group_key": f"grp_sha256:v1:{'e' * 64}",
            "tool": {"name": "codeql", "scan_type": "SAST"},
            "title": "Privilege check",
            "cwe_ids": ["CWE-400"],
            "location": {"kind": "code", "path": "routes/currentUser.ts", "start_line": 31},
            "evidence": {"kind": "code"},
        },
    ]


def test_build_analysis_groups_merges_sqli_and_separates_broad_cwe() -> None:
    findings = _sample_findings()
    groups = build_analysis_groups(findings)

    # 100% coverage check
    grouped_fps = set()
    for g in groups:
        for f in g.findings:
            grouped_fps.add(f["fingerprint"])
    input_fps = {f["fingerprint"] for f in findings}
    assert grouped_fps == input_fps

    # SQLi findings (login.ts semgrep + login.ts codeql + ZAP login) should be merged in 1 group
    sqli_group = None
    for g in groups:
        fps = {f["fingerprint"] for f in g.findings}
        if f"fp_sha256:v1:{'1' * 64}" in fps:
            sqli_group = g
            break
    assert sqli_group is not None
    sqli_fps = {f["fingerprint"] for f in sqli_group.findings}
    assert f"fp_sha256:v1:{'1' * 64}" in sqli_fps
    assert f"fp_sha256:v1:{'2' * 64}" in sqli_fps
    assert f"fp_sha256:v1:{'3' * 64}" in sqli_fps
    assert sqli_group.correlation_type == "sast_dast_suspected"

    # CWE-400 server.ts and currentUser.ts should NOT be merged
    server_fp = f"fp_sha256:v1:{'4' * 64}"
    user_fp = f"fp_sha256:v1:{'5' * 64}"
    for g in groups:
        fps = {f["fingerprint"] for f in g.findings}
        assert not (server_fp in fps and user_fp in fps), "CWE-400 across different files should not merge"
