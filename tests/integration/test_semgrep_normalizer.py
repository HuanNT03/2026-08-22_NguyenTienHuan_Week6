import json
from pathlib import Path

from src.normalizers.common.json_pointer import resolve_json_pointer
from src.normalizers.common.validation import build_validator, load_schema, validate_finding
from src.normalizers.context import NormalizationContext
from src.normalizers.semgrep import normalize_semgrep_report

ROOT = Path(__file__).resolve().parents[2]


def test_semgrep_report_normalizes_one_finding_per_result():
    report = json.loads((ROOT / "tests/fixtures/scanners/semgrep.json").read_text(encoding="utf-8"))
    context = NormalizationContext(
        schema_version="1.0.0",
        normalizer_version="1.0.0",
        run_id="semgrep_test",
        pipeline_run_id=None,
        scanned_at="2026-08-01T00:00:00Z",
        target_name="juice-shop",
        target_version="20.1.1",
        target_commit_sha="f915bddd82790d0f3018902d36ae9b4241a5f51f",
        target_base_url=None,
        report_path="tests/fixtures/scanners/semgrep.json",
    )
    result = normalize_semgrep_report(report, context, normalized_at="2026-08-01T01:00:00Z")
    assert len(result.findings) == len(report["results"])
    assert result.raw_counts["findings_written"] == len(report["results"])
    expected_data_flows = sum(
        raw_result.get("extra", {}).get("dataflow_trace") is not None for raw_result in report["results"]
    )
    assert expected_data_flows > 0
    assert sum(finding["data_flow"] is not None for finding in result.findings) == expected_data_flows

    validator = build_validator(load_schema(ROOT / "schemas/unified_findings.schema.json"))
    for index, finding in enumerate(result.findings):
        validate_finding(finding, validator)
        assert finding["rule"]["id"] == report["results"][index]["check_id"]
        assert not finding["location"]["path"].startswith("/")
        assert finding["fingerprint"].startswith("fp_sha256:v1:")
        assert finding["group_key"].startswith("grp_sha256:v1:")
        assert finding["evidence"] is None
        pointer = finding["raw_sources"][0]["json_pointer"]
        assert resolve_json_pointer(report, pointer) is report["results"][index]
