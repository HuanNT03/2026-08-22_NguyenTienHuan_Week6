import json
from pathlib import Path

from src.normalizers.common.json_pointer import resolve_json_pointer
from src.normalizers.common.validation import build_validator, load_schema, validate_finding
from src.normalizers.context import NormalizationContext
from src.normalizers.zap import normalize_zap_report

ROOT = Path(__file__).resolve().parents[2]


def test_zap_report_normalizes_one_finding_per_instance():
    report = json.loads((ROOT / "tests/fixtures/scanners/zap.json").read_text(encoding="utf-8"))
    expected_count = sum(
        len(alert.get("instances", []))
        for site in report["site"]
        for alert in site.get("alerts", [])
    )
    context = NormalizationContext(
        schema_version="1.0.0",
        normalizer_version="1.0.0",
        run_id="zap_test",
        pipeline_run_id=None,
        scanned_at="2026-08-01T00:00:00Z",
        target_name="juice-shop",
        target_version="20.1.1",
        target_commit_sha="f915bddd82790d0f3018902d36ae9b4241a5f51f",
        target_base_url="http://juice-shop:3000",
        report_path="tests/fixtures/scanners/zap.json",
    )
    result = normalize_zap_report(report, context, normalized_at="2026-08-01T01:00:00Z")
    assert len(result.findings) == expected_count
    assert result.warnings["text_parse_errors"] == 0
    validator = build_validator(load_schema(ROOT / "schemas/unified_findings.schema.json"))
    for finding in result.findings:
        validate_finding(finding, validator)
        assert finding["location"]["uri"]
        assert finding["location"]["endpoint"].startswith("/")
        assert finding["evidence"] is None
        assert "<p>" not in (finding["description"] or "")
        assert resolve_json_pointer(report, finding["raw_sources"][0]["json_pointer"])

    invalid_taxonomy = [
        finding for finding in result.findings
        if finding["rule"]["id"] == "10109"
    ]
    assert invalid_taxonomy
    assert all(finding["cwe_ids"] == [] and finding["wasc_ids"] == [] for finding in invalid_taxonomy)
