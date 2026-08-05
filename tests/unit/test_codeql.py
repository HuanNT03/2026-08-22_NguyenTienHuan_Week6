from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from src.normalizers.codeql import normalize_codeql_report
from src.normalizers.context import NormalizationContext


def _context(source_root: Path | None = None) -> NormalizationContext:
    return NormalizationContext(
        schema_version="2.0.0",
        normalizer_version="2.0.0",
        run_id="codeql_unit",
        pipeline_run_id=None,
        scanned_at="2026-08-05T00:00:00Z",
        target_name="juice-shop",
        target_version="20.1.1",
        target_commit_sha="f915bddd82790d0f3018902d36ae9b4241a5f51f",
        target_base_url=None,
        report_path="codeql.sarif",
        source_root=source_root,
    )


def _descriptor(rule_id: str, title: str, description: str) -> dict[str, Any]:
    return {
        "id": rule_id,
        "shortDescription": {"text": title},
        "fullDescription": {"text": description},
        "properties": {
            "name": title,
            "security-severity": "7.5",
            "precision": "high",
            "tags": ["external/cwe/cwe-089"],
        },
    }


def _result(rule_id: str = "js/test-rule", rule_index: int = 0) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "message": {"text": "Instance-specific alert"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": "routes/search.ts"},
                "region": {"startLine": 12, "startColumn": 4, "endLine": 12, "endColumn": 18},
            },
        }],
    }


def _report() -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "version": "2.26.0",
                    "rules": [_descriptor("js/test-rule", "Rule title", "Rule-level description")],
                },
            },
            "results": [_result()],
        }],
    }


def _normalize(report: dict[str, Any], source_root: Path | None = None):
    return normalize_codeql_report(report, _context(source_root), normalized_at="2026-08-05T01:00:00Z")


def test_result_message_precedes_rule_description() -> None:
    finding = _normalize(_report()).findings[0]

    assert finding["title"] == "Rule title"
    assert finding["description"] == "Instance-specific alert"
    assert finding["rule"]["name"] == "Rule title"


def test_description_falls_back_to_rule_full_description() -> None:
    report = _report()
    del report["runs"][0]["results"][0]["message"]

    finding = _normalize(report).findings[0]

    assert finding["description"] == "Rule-level description"


def test_mismatched_rule_index_falls_back_to_matching_rule_id() -> None:
    report = _report()
    report["runs"][0]["tool"]["driver"]["rules"] = [
        _descriptor("js/wrong-rule", "Wrong title", "Wrong description"),
        _descriptor("js/test-rule", "Expected title", "Expected description"),
    ]
    result = report["runs"][0]["results"][0]
    result["ruleIndex"] = 0
    del result["message"]

    normalized = _normalize(report)
    finding = normalized.findings[0]

    assert finding["title"] == "Expected title"
    assert finding["description"] == "Expected description"
    assert finding["raw_sources"][1]["json_pointer"].endswith("/rules/1")
    assert normalized.warnings["missing_rule_descriptors"] == 0


def test_missing_rule_descriptor_is_reported_without_fabricating_metadata() -> None:
    report = _report()
    report["runs"][0]["tool"]["driver"]["rules"] = []

    normalized = _normalize(report)
    finding = normalized.findings[0]

    assert finding["title"] is None
    assert finding["description"] == "Instance-specific alert"
    assert finding["cwe_ids"] == []
    assert len(finding["raw_sources"]) == 1
    assert normalized.warnings["missing_rule_descriptors"] == 1


def test_region_snippet_is_direct_evidence_without_changing_data_flow() -> None:
    report = _report()
    result = report["runs"][0]["results"][0]
    result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
        "text": "const result = unsafe(input)"
    }
    result["codeFlows"] = [{
        "threadFlows": [{
            "locations": [
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "routes/search.ts"},
                            "region": {
                                "startLine": 8,
                                "snippet": {"text": "const input = req.query.q"},
                            },
                        },
                        "message": {"text": "req.query.q"},
                    },
                },
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "routes/search.ts"},
                            "region": {
                                "startLine": 12,
                                "snippet": {"text": "const result = unsafe(input)"},
                            },
                        },
                        "message": {"text": "unsafe(input)"},
                    },
                },
            ],
        }],
    }]

    finding = _normalize(report).findings[0]

    assert finding["evidence"]["quality"] == "direct"
    assert finding["evidence"]["code_evidence"]["code_snippet"]["content"] == "const result = unsafe(input)"
    assert finding["data_flow"] is not None
    assert finding["data_flow"][0]["source"]["content"] is None
    assert finding["data_flow"][0]["sink"]["content"] is None


def test_missing_end_line_falls_back_to_start_line() -> None:
    report = _report()
    del report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["endLine"]

    finding = _normalize(report).findings[0]

    assert finding["location"]["start_line"] == 12
    assert finding["location"]["end_line"] == 12
    assert finding["evidence"]["provenance"].endswith("lines=12-12")


def test_context_region_snippet_is_used_after_region_snippet() -> None:
    report = _report()
    physical = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    physical["contextRegion"] = {"snippet": {"text": "context scanner snippet"}}

    finding = _normalize(report).findings[0]

    assert finding["evidence"]["quality"] == "direct"
    assert finding["evidence"]["code_evidence"]["code_snippet"]["content"] == "context scanner snippet"


def test_source_fallback_is_enriched_and_adds_context(tmp_path: Path) -> None:
    source = tmp_path / "routes/search.ts"
    source.parent.mkdir(parents=True)
    source.write_text("\n".join(f"line {number}" for number in range(1, 20)) + "\n", encoding="utf-8")

    finding = _normalize(_report(), tmp_path).findings[0]
    snippet = finding["evidence"]["code_evidence"]["code_snippet"]

    assert finding["evidence"]["quality"] == "enriched"
    assert snippet["content"] == "line 12"
    assert [item["line"] for item in snippet["context_before"]] == [7, 8, 9, 10, 11]
    assert [item["line"] for item in snippet["context_after"]] == [13, 14, 15, 16, 17]


@pytest.mark.parametrize("field", ["relatedLocations", "codeFlows"])
def test_flow_or_related_location_without_source_is_inferred(field: str) -> None:
    report = _report()
    result = report["runs"][0]["results"][0]
    if field == "relatedLocations":
        result[field] = [{"physicalLocation": {"artifactLocation": {"uri": "routes/input.ts"}}}]
    else:
        result[field] = [{}]

    finding = _normalize(report).findings[0]

    assert finding["evidence"]["quality"] == "inferred"


def test_without_snippet_source_or_flow_quality_is_none() -> None:
    finding = _normalize(_report()).findings[0]

    assert finding["evidence"]["quality"] == "none"
    assert finding["evidence"]["code_evidence"]["code_snippet"]["content"] is None


def test_related_context_allows_missing_id_message_and_artifact_uri_fallback() -> None:
    report = _report()
    run = report["runs"][0]
    run["artifacts"] = [{"location": {"uri": "routes/related.ts"}}]
    run["results"][0]["relatedLocations"] = [{
        "physicalLocation": {
            "artifactLocation": {"index": 0},
            "region": {"startLine": 19},
        },
    }]

    finding = _normalize(report).findings[0]

    assert finding["evidence"]["code_evidence"]["related_context"] == [{
        "id": None,
        "message": None,
        "path": "routes/related.ts",
        "line": 19,
    }]


def test_primary_artifact_uri_falls_back_to_artifact_index() -> None:
    report = _report()
    run = report["runs"][0]
    run["artifacts"] = [{"location": {"uri": "routes/search.ts"}}]
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0}

    finding = _normalize(report).findings[0]

    assert finding["location"]["path"] == "routes/search.ts"


@pytest.mark.parametrize(
    ("mutate", "error", "message"),
    [
        (lambda report: report.update(version="2.0.0"), ValueError, "Unsupported SARIF version"),
        (lambda report: report.update(runs={}), TypeError, "runs must be an array"),
        (lambda report: report["runs"].__setitem__(0, []), TypeError, "run 0 must be an object"),
        (
            lambda report: report["runs"][0]["results"][0].pop("ruleId"),
            ValueError,
            "missing ruleId",
        ),
        (
            lambda report: report["runs"][0]["results"][0].pop("locations"),
            ValueError,
            "missing primary location",
        ),
        (
            lambda report: report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"].pop(
                "startLine"
            ),
            ValueError,
            "incomplete primary location",
        ),
    ],
)
def test_invalid_sarif_structures_fail_with_context(mutate, error, message) -> None:
    report = deepcopy(_report())
    mutate(report)

    with pytest.raises(error, match=message):
        _normalize(report)
