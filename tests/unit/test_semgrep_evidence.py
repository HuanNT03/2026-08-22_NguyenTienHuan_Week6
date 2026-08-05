from pathlib import Path

from src.normalizers.context import NormalizationContext
from src.normalizers.semgrep import normalize_semgrep_report


def _context(source_root: Path | None = None) -> NormalizationContext:
    return NormalizationContext(
        schema_version="2.0.0",
        normalizer_version="2.0.0",
        run_id="semgrep-unit",
        pipeline_run_id=None,
        scanned_at="2026-08-05T00:00:00Z",
        target_name="juice-shop",
        target_version="20.1.1",
        target_commit_sha="f915bddd82790d0f3018902d36ae9b4241a5f51f",
        target_base_url=None,
        report_path="reports/raw/semgrep.json",
        source_root=source_root,
    )


def _report(lines="  sink(input)\n"):
    return {
        "version": "1.171.0",
        "results": [{
            "check_id": "typescript.test-rule",
            "path": "/src/target-app/juice-shop/routes/example.ts",
            "start": {"line": 3, "col": 3},
            "end": {"line": 3, "col": 14},
            "extra": {
                "lines": lines,
                "message": "test",
                "severity": "WARNING",
                "metadata": {},
                "metavars": {
                    "$Z_VALUE": {"abstract_content": "  zed"},
                    "$A_VALUE": {},
                },
            },
        }],
        "errors": [],
    }


def test_semgrep_direct_evidence_preserves_text_and_sorts_metavars(tmp_path: Path) -> None:
    source = tmp_path / "routes/example.ts"
    source.parent.mkdir(parents=True)
    source.write_text("before one\nbefore two\n  sink(input)\nafter\n", encoding="utf-8")

    finding = normalize_semgrep_report(
        _report(),
        _context(tmp_path),
        normalized_at="2026-08-05T01:00:00Z",
    ).findings[0]
    evidence = finding["evidence"]

    assert evidence["quality"] == "direct"
    assert evidence["provenance"] == "semgrep.json:results[0].extra.lines"
    assert evidence["code_evidence"]["code_snippet"] == {
        "content": "  sink(input)\n",
        "context_before": [
            {"line": 1, "content": "before one"},
            {"line": 2, "content": "before two"},
        ],
        "context_after": [{"line": 4, "content": "after"}],
    }
    assert evidence["code_evidence"]["matched_contents"] == [
        {"name": "$A_VALUE", "content": None},
        {"name": "$Z_VALUE", "content": "  zed"},
    ]


def test_semgrep_missing_lines_is_none_with_nonempty_provenance() -> None:
    finding = normalize_semgrep_report(
        _report(lines=""),
        _context(),
        normalized_at="2026-08-05T01:00:00Z",
    ).findings[0]

    assert finding["evidence"]["quality"] == "none"
    assert finding["evidence"]["code_evidence"]["code_snippet"]["content"] is None
    assert finding["evidence"]["provenance"]
