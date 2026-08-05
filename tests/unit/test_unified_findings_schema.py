import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from src.normalizers.common.validation import build_validator, load_schema

ROOT = Path(__file__).resolve().parents[2]
V2_SCHEMA = ROOT / "schemas/unified_findings.schema.json"
V1_SCHEMA = ROOT / "tests/fixtures/schemas/unified_findings-1.0.0.schema.json"


def _code_evidence() -> dict[str, Any]:
    return {
        "kind": "code",
        "code_evidence": {
            "code_snippet": {"content": None, "context_before": [], "context_after": []},
            "matched_contents": [],
            "related_context": [{"id": None, "message": None, "path": None, "line": None}],
            "redacted": False,
            "truncated": False,
        },
        "http_evidence": None,
        "quality": "none",
        "provenance": "semgrep.json:results[0].extra.lines",
    }


def _http_evidence() -> dict[str, Any]:
    return {
        "kind": "http",
        "code_evidence": None,
        "http_evidence": {
            "request_excerpt": None,
            "matched_evidence": None,
            "context_note": None,
            "attack_payload": None,
            "redacted": False,
            "truncated": False,
        },
        "quality": "none",
        "provenance": "zap.json:site[0].alerts[0].instances[0]",
    }


def _finding(evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema_version": "2.0.0",
        "finding_id": "fnd_00000000000000000000000000000001",
        "fingerprint": f"fp_sha256:v1:{'0' * 64}",
        "group_key": f"grp_sha256:v1:{'1' * 64}",
        "tool": {"name": "semgrep", "version": "1.171.0", "scan_type": "SAST"},
        "scan": {"run_id": "schema-test", "pipeline_run_id": None, "scanned_at": "2026-08-05T00:00:00Z"},
        "target": {
            "name": "juice-shop",
            "version": "20.1.1",
            "commit_sha": "f915bddd82790d0f3018902d36ae9b4241a5f51f",
            "base_url": None,
        },
        "rule": {"id": "rule", "reference_id": None, "name": None, "native_severity": None, "native_confidence": None},
        "title": None,
        "description": None,
        "categories": [],
        "severity": "unknown",
        "confidence": "unknown",
        "cwe_ids": [],
        "owasp_categories": [],
        "wasc_ids": [],
        "location": {
            "kind": "code",
            "path": "routes/example.ts",
            "start_line": 1,
            "start_column": None,
            "end_line": 1,
            "end_column": None,
        },
        "evidence": evidence if evidence is not None else _code_evidence(),
        "data_flow": None,
        "solution": None,
        "references": [],
        "normalization": {"normalizer_version": "2.0.0", "normalized_at": "2026-08-05T01:00:00Z"},
        "raw_sources": [{"format": "semgrep-json", "report_path": "semgrep.json", "json_pointer": "/results/0"}],
    }


def _errors(finding: dict[str, Any]) -> list[Any]:
    return list(build_validator(load_schema(V2_SCHEMA)).iter_errors(finding))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda finding: finding.pop("evidence"),
        lambda finding: finding.update(evidence=None),
        lambda finding: finding["evidence"].pop("provenance"),
        lambda finding: finding["evidence"].update(provenance=""),
        lambda finding: finding["evidence"].update(code_evidence=None),
        lambda finding: finding["evidence"].update(http_evidence=_http_evidence()["http_evidence"]),
        lambda finding: finding["evidence"].update(quality="trusted"),
        lambda finding: finding["evidence"].update(extra=True),
        lambda finding: finding["evidence"]["code_evidence"].update(extra=True),
    ],
)
def test_invalid_code_evidence_is_rejected(mutate) -> None:
    finding = _finding()
    mutate(finding)
    assert _errors(finding)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda evidence: evidence.update(http_evidence=None),
        lambda evidence: evidence.update(code_evidence=_code_evidence()["code_evidence"]),
        lambda evidence: evidence["http_evidence"].update(extra=True),
    ],
)
def test_invalid_http_evidence_is_rejected(mutate) -> None:
    evidence = _http_evidence()
    mutate(evidence)
    assert _errors(_finding(evidence))


def test_valid_code_and_http_evidence_are_accepted() -> None:
    assert _errors(_finding(_code_evidence())) == []
    http_finding = _finding(_http_evidence())
    http_finding["tool"] = {"name": "zap", "version": "2.17.0", "scan_type": "DAST"}
    http_finding["location"] = {
        "kind": "http",
        "uri": "http://juice-shop:3000/",
        "endpoint": "/",
        "method": None,
        "parameter": None,
    }
    assert _errors(http_finding) == []


def test_v1_and_v2_schemas_reject_the_other_contract() -> None:
    v2 = _finding()
    v1 = deepcopy(v2)
    v1["schema_version"] = "1.0.0"
    v1["normalization"]["normalizer_version"] = "1.0.0"
    v1["evidence"] = None

    v1_validator = build_validator(load_schema(V1_SCHEMA))
    v2_validator = build_validator(load_schema(V2_SCHEMA))

    assert list(v2_validator.iter_errors(v1))
    assert list(v1_validator.iter_errors(v2))


def test_schema_id_and_versions_are_v2() -> None:
    schema = json.loads(V2_SCHEMA.read_text(encoding="utf-8"))
    assert schema["$id"] == "https://sentinel.local/schemas/unified-findings/2.0.0/schema.json"
    assert schema["properties"]["schema_version"]["const"] == "2.0.0"
    assert schema["$defs"]["normalization"]["properties"]["normalizer_version"]["const"] == "2.0.0"
