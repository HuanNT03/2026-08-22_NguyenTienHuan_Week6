import json
import re
import shutil
from pathlib import Path

from src.normalizers import cli
from src.normalizers.common.validation import build_validator, load_schema, validate_finding

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas/unified_findings.schema.json"
SOURCE_FIXTURE_ROOT = ROOT / "tests/fixtures/source/juice-shop"


def _metadata() -> dict[str, object]:
    return {
        "run_id": "cli_test",
        "pipeline_run_id": None,
        "scanned_at": "2026-08-05T00:00:00Z",
        "target": {
            "name": "juice-shop",
            "version": "20.1.1",
            "commit_sha": "f915bddd82790d0f3018902d36ae9b4241a5f51f",
            "base_url": "http://juice-shop:3000",
        },
    }


def _codeql_report() -> dict[str, object]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "version": "2.26.0",
                        "rules": [
                            {
                                "id": "js/test-rule",
                                "shortDescription": {"text": "Test rule"},
                                "fullDescription": {"text": "Rule description"},
                                "properties": {"precision": "high", "security-severity": "7.5", "tags": []},
                            }
                        ],
                    },
                },
                "results": [
                    {
                        "ruleId": "js/test-rule",
                        "ruleIndex": 0,
                        "message": {"text": "Finding description"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "routes/search.ts"},
                                    "region": {"startLine": 12, "startColumn": 4},
                                },
                            }
                        ],
                    }
                ],
            }
        ],
    }


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _fixed_clock(monkeypatch) -> None:
    monkeypatch.setattr(cli, "utc_now", lambda: "2026-08-05T01:00:00Z")


def test_single_tool_cli_writes_timestamped_jsonl_and_prints_exact_path(tmp_path: Path, monkeypatch, capsys) -> None:
    _fixed_clock(monkeypatch)
    report = tmp_path / "codeql.sarif"
    metadata = tmp_path / "codeql.meta.json"
    output_dir = tmp_path / "normalized"
    output = output_dir / "unified-findings-20260805T010000Z.jsonl"
    summary = tmp_path / "summary.json"
    _write_json(report, _codeql_report())
    _write_json(metadata, _metadata())

    status = cli.main(
        [
            "--tool",
            "codeql",
            "--input",
            str(report),
            "--metadata",
            str(metadata),
            "--output-dir",
            str(output_dir),
            "--source-root",
            str(SOURCE_FIXTURE_ROOT),
            "--summary",
            str(summary),
            "--schema",
            str(SCHEMA_PATH),
        ]
    )

    captured = capsys.readouterr()
    assert status == 0
    assert re.fullmatch(r"unified-findings-\d{8}T\d{6}Z\.jsonl", output.name)
    assert captured.out.strip() == output.as_posix()
    assert not (output.parent / f".{output.name}.tmp").exists()
    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["description"] == "Finding description"
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["normalized_at"] == "2026-08-05T01:00:00Z"
    assert payload["output_path"] == output.as_posix()
    assert payload["total_findings_written"] == 1
    assert payload["tools"]["codeql"]["status"] == "success"
    assert payload["tools"]["codeql"]["warnings"]["source_evidence_errors"] == 0
    assert payload["tools"]["semgrep"]["status"] == "skipped"


def test_single_tool_cli_marks_missing_source_evidence_partial(tmp_path: Path, monkeypatch) -> None:
    """Keep a valid CodeQL finding while reporting unavailable source enrichment as partial."""
    _fixed_clock(monkeypatch)
    report = tmp_path / "codeql.sarif"
    metadata = tmp_path / "codeql.meta.json"
    output_dir = tmp_path / "normalized"
    output = output_dir / "unified-findings-20260805T010000Z.jsonl"
    summary = tmp_path / "summary.json"
    _write_json(report, _codeql_report())
    _write_json(metadata, _metadata())

    status = cli.main(
        [
            "--tool",
            "codeql",
            "--input",
            str(report),
            "--metadata",
            str(metadata),
            "--output-dir",
            str(output_dir),
            "--source-root",
            str(tmp_path / "missing-source"),
            "--summary",
            str(summary),
            "--schema",
            str(SCHEMA_PATH),
        ]
    )

    finding = json.loads(output.read_text(encoding="utf-8").strip())
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert status == 0
    assert finding["evidence"]["quality"] == "none"
    assert finding["evidence"]["code_evidence"]["code_snippet"] == {
        "content": None,
        "context_before": [],
        "context_after": [],
    }
    assert payload["output_path"] == output.as_posix()
    assert payload["total_findings_written"] == 1
    assert payload["tools"]["codeql"]["status"] == "partial"
    assert payload["tools"]["codeql"]["warnings"]["source_evidence_errors"] == 1


def test_normalize_all_keeps_successful_tools_when_one_report_is_malformed(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    _fixed_clock(monkeypatch)
    raw_dir = tmp_path / "raw"
    _write_json(raw_dir / "codeql.sarif", _codeql_report())
    _write_json(raw_dir / "zap.json", {"site": []})
    (raw_dir / "semgrep.json").write_text("{broken\n", encoding="utf-8")
    for tool in cli.TOOLS:
        _write_json(raw_dir / f"{tool}.meta.json", _metadata())
    output_dir = tmp_path / "normalized"
    output = output_dir / "unified-findings-20260805T010000Z.jsonl"
    summary = tmp_path / "summary.json"

    status = cli.main(
        [
            "normalize-all",
            "--raw-dir",
            str(raw_dir),
            "--output-dir",
            str(output_dir),
            "--source-root",
            str(SOURCE_FIXTURE_ROOT),
            "--summary",
            str(summary),
            "--schema",
            str(SCHEMA_PATH),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert status == 1
    assert len(output.read_text(encoding="utf-8").splitlines()) == 1
    assert payload["tools"]["semgrep"]["status"] == "failed"
    assert payload["tools"]["zap"]["status"] == "success"
    assert payload["tools"]["codeql"]["status"] == "success"
    assert payload["tools"]["codeql"]["warnings"]["source_evidence_errors"] == 0
    assert "semgrep: normalization failed" in captured.err
    assert "Traceback" not in captured.err


def test_invalid_schema_returns_structured_failure_without_traceback(tmp_path: Path, monkeypatch, capsys) -> None:
    _fixed_clock(monkeypatch)
    report = tmp_path / "codeql.sarif"
    metadata = tmp_path / "codeql.meta.json"
    output_dir = tmp_path / "normalized"
    output = output_dir / "unified-findings-20260805T010000Z.jsonl"
    summary = tmp_path / "summary.json"
    schema = tmp_path / "invalid.schema.json"
    _write_json(report, _codeql_report())
    _write_json(metadata, _metadata())
    _write_json(schema, {"type": "not-a-json-schema-type"})
    output_dir.mkdir(parents=True)
    output.write_text("stale output\n", encoding="utf-8")

    status = cli.main(
        [
            "--tool",
            "codeql",
            "--input",
            str(report),
            "--metadata",
            str(metadata),
            "--output-dir",
            str(output_dir),
            "--summary",
            str(summary),
            "--schema",
            str(schema),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert status == 1
    assert not output.exists()
    assert payload["total_findings_written"] == 0
    assert payload["tools"]["codeql"]["status"] == "failed"
    assert payload["tools"]["semgrep"]["status"] == "skipped"
    assert "schema: normalization setup failed" in captured.err
    assert "Traceback" not in captured.err


def test_invalid_metadata_fails_selected_tool_and_removes_stale_output(tmp_path: Path, monkeypatch, capsys) -> None:
    _fixed_clock(monkeypatch)
    report = tmp_path / "codeql.sarif"
    metadata = tmp_path / "codeql.meta.json"
    output_dir = tmp_path / "normalized"
    output = output_dir / "unified-findings-20260805T010000Z.jsonl"
    summary = tmp_path / "summary.json"
    _write_json(report, _codeql_report())
    _write_json(metadata, {"run_id": "missing-target"})
    output_dir.mkdir(parents=True)
    output.write_text("stale output\n", encoding="utf-8")

    status = cli.main(
        [
            "--tool",
            "codeql",
            "--input",
            str(report),
            "--metadata",
            str(metadata),
            "--output-dir",
            str(output_dir),
            "--summary",
            str(summary),
            "--schema",
            str(SCHEMA_PATH),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert status == 1
    assert not output.exists()
    assert payload["tools"]["codeql"]["status"] == "failed"
    assert "Metadata target must be an object" in captured.err
    assert "Traceback" not in captured.err


def test_normalize_all_skips_missing_pairs_when_one_tool_succeeds(tmp_path: Path, monkeypatch, capsys) -> None:
    _fixed_clock(monkeypatch)
    raw_dir = tmp_path / "raw"
    _write_json(raw_dir / "codeql.sarif", _codeql_report())
    _write_json(raw_dir / "codeql.meta.json", _metadata())
    output_dir = tmp_path / "normalized"
    output = output_dir / "unified-findings-20260805T010000Z.jsonl"
    summary = tmp_path / "summary.json"

    status = cli.main(
        [
            "normalize-all",
            "--raw-dir",
            str(raw_dir),
            "--output-dir",
            str(output_dir),
            "--source-root",
            str(SOURCE_FIXTURE_ROOT),
            "--summary",
            str(summary),
            "--schema",
            str(SCHEMA_PATH),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert status == 0
    assert len(output.read_text(encoding="utf-8").splitlines()) == 1
    assert payload["total_findings_written"] == 1
    assert payload["tools"]["codeql"]["status"] == "success"
    assert payload["tools"]["codeql"]["warnings"]["source_evidence_errors"] == 0
    for tool, report_name in (("semgrep", "semgrep.json"), ("zap", "zap.json")):
        tool_summary = payload["tools"][tool]
        assert tool_summary["status"] == "skipped"
        assert tool_summary["reason"] == "missing_input"
        assert tool_summary["missing_files"] == [
            (raw_dir / report_name).as_posix(),
            (raw_dir / f"{tool}.meta.json").as_posix(),
        ]
    assert "semgrep: skipped: missing input file(s)" in captured.err
    assert "zap: skipped: missing input file(s)" in captured.err


def test_missing_metadata_skips_only_that_scanner(tmp_path: Path, monkeypatch) -> None:
    _fixed_clock(monkeypatch)
    raw_dir = tmp_path / "raw"
    _write_json(raw_dir / "codeql.sarif", _codeql_report())
    _write_json(raw_dir / "zap.json", {"site": []})
    _write_json(raw_dir / "zap.meta.json", _metadata())
    output_dir = tmp_path / "normalized"
    output = output_dir / "unified-findings-20260805T010000Z.jsonl"
    summary = tmp_path / "summary.json"

    status = cli.main(
        [
            "normalize-all",
            "--raw-dir",
            str(raw_dir),
            "--output-dir",
            str(output_dir),
            "--summary",
            str(summary),
            "--schema",
            str(SCHEMA_PATH),
        ]
    )

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert status == 0
    assert output.exists()
    assert payload["tools"]["zap"]["status"] == "success"
    assert payload["tools"]["codeql"] == {
        "status": "skipped",
        "findings_written": 0,
        "warnings": {},
        "reason": "missing_input",
        "missing_files": [(raw_dir / "codeql.meta.json").as_posix()],
    }


def test_all_missing_inputs_exit_nonzero_without_success_output(tmp_path: Path, monkeypatch, capsys) -> None:
    _fixed_clock(monkeypatch)
    raw_dir = tmp_path / "raw"
    output_dir = tmp_path / "normalized"
    output = output_dir / "unified-findings-20260805T010000Z.jsonl"
    summary = tmp_path / "summary.json"
    output_dir.mkdir(parents=True)
    output.write_text("stale output\n", encoding="utf-8")

    status = cli.main(
        [
            "normalize-all",
            "--raw-dir",
            str(raw_dir),
            "--output-dir",
            str(output_dir),
            "--summary",
            str(summary),
            "--schema",
            str(SCHEMA_PATH),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert status == 1
    assert not output.exists()
    assert payload["total_findings_written"] == 0
    assert all(payload["tools"][tool]["reason"] == "missing_input" for tool in cli.TOOLS)
    assert "Traceback" not in captured.err


def test_full_curated_fixture_run_filters_external_zap_records(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    fixture_dir = ROOT / "tests/fixtures/scanners"
    for tool, report_name in cli.REPORT_NAMES.items():
        shutil.copyfile(fixture_dir / report_name, raw_dir / report_name)
        metadata = _metadata()
        metadata["run_id"] = f"{tool}_fixture"
        _write_json(raw_dir / f"{tool}.meta.json", metadata)
    output_dir = tmp_path / "normalized"
    summary = output_dir / "normalization-summary.json"

    clock_calls = 0

    def fixed_clock() -> str:
        nonlocal clock_calls
        clock_calls += 1
        return "2026-08-05T08:00:00+07:00"

    status = cli.main(
        [
            "normalize-all",
            "--raw-dir",
            str(raw_dir),
            "--output-dir",
            str(output_dir),
            "--source-root",
            str(tmp_path / "missing-source"),
            "--summary",
            str(summary),
            "--schema",
            str(SCHEMA_PATH),
        ],
        clock=fixed_clock,
    )

    output = output_dir / "unified-findings-20260805T010000Z.jsonl"
    findings = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    validator = build_validator(load_schema(SCHEMA_PATH))
    for finding in findings:
        validate_finding(finding, validator)

    assert status == 0
    assert clock_calls == 1
    assert len(findings) == 160
    assert {finding["schema_version"] for finding in findings} == {"2.0.0"}
    assert {finding["normalization"]["normalized_at"] for finding in findings} == {"2026-08-05T01:00:00Z"}
    assert sum(finding["tool"]["name"] == "semgrep" for finding in findings) == 37
    assert sum(finding["tool"]["name"] == "codeql" for finding in findings) == 87
    zap_findings = [finding for finding in findings if finding["tool"]["name"] == "zap"]
    assert len(zap_findings) == 36
    assert {
        quality: sum(finding["evidence"]["quality"] == quality for finding in zap_findings)
        for quality in ("direct", "inferred", "none")
    } == {"direct": 24, "inferred": 5, "none": 7}
    summary_payload = json.loads(summary.read_text(encoding="utf-8"))
    assert summary_payload["tools"]["zap"]["status"] == "partial"
    assert summary_payload["tools"]["zap"]["warnings"]["out_of_scope_instances_filtered"] == 50
    assert summary_payload["tools"]["zap"]["warnings"]["out_of_scope_unique_uri_count"] == 19
