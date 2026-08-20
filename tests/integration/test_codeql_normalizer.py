import json
from pathlib import Path
from typing import Any

from src.normalizers.codeql import normalize_codeql_report
from src.normalizers.common.json_pointer import resolve_json_pointer
from src.normalizers.common.validation import build_validator, load_schema, validate_finding
from src.normalizers.context import NormalizationContext

ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = "tests/fixtures/scanners/codeql.sarif"


def _raw_results(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [result for run in report["runs"] for result in run.get("results", [])]


def test_codeql_report_normalizes_one_finding_per_result():
    report = json.loads((ROOT / REPORT_PATH).read_text(encoding="utf-8"))
    raw_results = _raw_results(report)
    assert raw_results
    assert (
        sum(
            raw_result["locations"][0]["physicalLocation"]["region"].get("endLine") is None
            for raw_result in raw_results
        )
        == 85
    )
    assert all(
        raw_result["locations"][0]["physicalLocation"]["contextRegion"]["snippet"]["text"] for raw_result in raw_results
    )

    context = NormalizationContext(
        schema_version="2.0.0",
        normalizer_version="2.0.0",
        run_id="codeql_test",
        pipeline_run_id=None,
        scanned_at="2026-08-03T00:00:00Z",
        target_name="juice-shop",
        target_version="20.1.1",
        target_commit_sha="f915bddd82790d0f3018902d36ae9b4241a5f51f",
        target_base_url=None,
        report_path=REPORT_PATH,
    )
    result = normalize_codeql_report(report, context, normalized_at="2026-08-03T01:00:00Z")

    assert len(result.findings) == len(raw_results)
    assert result.raw_counts == {
        "raw_findings": len(raw_results),
        "findings_written": len(raw_results),
    }
    assert sum(finding["data_flow"] is not None for finding in result.findings) == 48
    assert result.warnings == {
        "extraction_errors": 0,
        "parse_errors": 0,
        "affected_files": 0,
        "missing_rule_descriptors": 0,
        "fingerprint_collisions": 0,
        "source_evidence_errors": 87,
    }

    validator = build_validator(load_schema(ROOT / "schemas/unified_findings.schema.json"))
    for finding, raw_result in zip(result.findings, raw_results, strict=True):
        validate_finding(finding, validator)
        assert finding["tool"] == {
            "name": "codeql",
            "version": "2.26.0",
            "scan_type": "SAST",
        }
        assert finding["rule"]["id"] == raw_result["ruleId"]
        assert finding["location"]["kind"] == "code"
        assert not finding["location"]["path"].startswith("/")
        assert finding["location"]["start_line"] > 0
        assert finding["fingerprint"].startswith("fp_sha256:v1:")
        assert finding["group_key"].startswith("grp_sha256:v1:")
        assert finding["schema_version"] == "2.0.0"
        assert finding["evidence"]["kind"] == "code"
        assert finding["evidence"]["quality"] == "direct"
        assert finding["evidence"]["code_evidence"]["matched_contents"] == []
        assert finding["evidence"]["http_evidence"] is None
        assert finding["evidence"]["provenance"].startswith("codeql.sarif:path=")
        raw_region = raw_result["locations"][0]["physicalLocation"]["region"]
        if raw_region.get("endLine") is None:
            assert finding["location"]["end_line"] == finding["location"]["start_line"]

        result_source = finding["raw_sources"][0]
        assert result_source["format"] == "codeql-sarif"
        assert result_source["report_path"] == REPORT_PATH
        assert resolve_json_pointer(report, result_source["json_pointer"]) is raw_result

        assert len(finding["raw_sources"]) == 2
        for rule_source in finding["raw_sources"][1:]:
            assert rule_source["format"] == "codeql-sarif-rule"
            rule = resolve_json_pointer(report, rule_source["json_pointer"])
            assert rule["id"] == finding["rule"]["id"]

        for data_flow in finding["data_flow"] or []:
            assert data_flow["kind"] == "taint"
            assert data_flow["engine"] == "codeql"
            assert data_flow["source"]["step_index"] == 0
            assert data_flow["sink"]["step_index"] >= 1

    related_context = [
        related for finding in result.findings for related in finding["evidence"]["code_evidence"]["related_context"]
    ]
    assert any(item["id"] is None for item in related_context)
    assert any(item["message"] is None for item in related_context)
