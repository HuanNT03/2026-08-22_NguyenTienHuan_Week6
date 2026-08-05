import json
from pathlib import Path

from src.normalizers import cli

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas/unified_findings.schema.json"


def _metadata() -> dict[str, object]:
    return {
        "run_id": "cli_test",
        "pipeline_run_id": None,
        "scanned_at": "2026-08-05T00:00:00Z",
        "target": {
            "name": "juice-shop",
            "version": "20.1.1",
            "commit_sha": "f915bddd82790d0f3018902d36ae9b4241a5f51f",
            "base_url": None,
        },
    }


def _codeql_report() -> dict[str, object]:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "version": "2.26.0",
                    "rules": [{
                        "id": "js/test-rule",
                        "shortDescription": {"text": "Test rule"},
                        "fullDescription": {"text": "Rule description"},
                        "properties": {"precision": "high", "security-severity": "7.5", "tags": []},
                    }],
                },
            },
            "results": [{
                "ruleId": "js/test-rule",
                "ruleIndex": 0,
                "message": {"text": "Finding description"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "routes/search.ts"},
                        "region": {"startLine": 12, "startColumn": 4},
                    },
                }],
            }],
        }],
    }


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _fixed_clock(monkeypatch) -> None:
    monkeypatch.setattr(cli, "utc_now", lambda: "2026-08-05T01:00:00Z")


def test_single_tool_cli_writes_valid_jsonl_and_summary(tmp_path: Path, monkeypatch) -> None:
    _fixed_clock(monkeypatch)
    report = tmp_path / "codeql.sarif"
    metadata = tmp_path / "codeql.meta.json"
    output = tmp_path / "unified-findings.jsonl"
    summary = tmp_path / "summary.json"
    _write_json(report, _codeql_report())
    _write_json(metadata, _metadata())

    status = cli.main([
        "--tool", "codeql",
        "--input", str(report),
        "--metadata", str(metadata),
        "--output", str(output),
        "--summary", str(summary),
        "--schema", str(SCHEMA_PATH),
    ])

    assert status == 0
    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["description"] == "Finding description"
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["normalized_at"] == "2026-08-05T01:00:00Z"
    assert payload["total_findings_written"] == 1
    assert payload["tools"]["codeql"]["status"] == "success"
    assert payload["tools"]["semgrep"]["status"] == "skipped"


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
    output = tmp_path / "unified-findings.jsonl"
    summary = tmp_path / "summary.json"

    status = cli.main([
        "normalize-all",
        "--raw-dir", str(raw_dir),
        "--output", str(output),
        "--summary", str(summary),
        "--schema", str(SCHEMA_PATH),
    ])

    captured = capsys.readouterr()
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert status == 1
    assert len(output.read_text(encoding="utf-8").splitlines()) == 1
    assert payload["tools"]["semgrep"]["status"] == "failed"
    assert payload["tools"]["zap"]["status"] == "success"
    assert payload["tools"]["codeql"]["status"] == "success"
    assert "semgrep: normalization failed" in captured.err
    assert "Traceback" not in captured.err


def test_invalid_schema_returns_structured_failure_without_traceback(tmp_path: Path, monkeypatch, capsys) -> None:
    _fixed_clock(monkeypatch)
    report = tmp_path / "codeql.sarif"
    metadata = tmp_path / "codeql.meta.json"
    output = tmp_path / "unified-findings.jsonl"
    summary = tmp_path / "summary.json"
    schema = tmp_path / "invalid.schema.json"
    _write_json(report, _codeql_report())
    _write_json(metadata, _metadata())
    _write_json(schema, {"type": "not-a-json-schema-type"})
    output.write_text("stale output\n", encoding="utf-8")

    status = cli.main([
        "--tool", "codeql",
        "--input", str(report),
        "--metadata", str(metadata),
        "--output", str(output),
        "--summary", str(summary),
        "--schema", str(schema),
    ])

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
    output = tmp_path / "unified-findings.jsonl"
    summary = tmp_path / "summary.json"
    _write_json(report, _codeql_report())
    _write_json(metadata, {"run_id": "missing-target"})
    output.write_text("stale output\n", encoding="utf-8")

    status = cli.main([
        "--tool", "codeql",
        "--input", str(report),
        "--metadata", str(metadata),
        "--output", str(output),
        "--summary", str(summary),
        "--schema", str(SCHEMA_PATH),
    ])

    captured = capsys.readouterr()
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert status == 1
    assert not output.exists()
    assert payload["tools"]["codeql"]["status"] == "failed"
    assert "Metadata target must be an object" in captured.err
    assert "Traceback" not in captured.err
