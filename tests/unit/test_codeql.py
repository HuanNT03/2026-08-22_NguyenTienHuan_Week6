from copy import deepcopy
from typing import Any

import pytest

from src.normalizers.codeql import normalize_codeql_report
from src.normalizers.context import NormalizationContext


def _context() -> NormalizationContext:
    return NormalizationContext(
        schema_version="1.0.0",
        normalizer_version="1.0.0",
        run_id="codeql_unit",
        pipeline_run_id=None,
        scanned_at="2026-08-05T00:00:00Z",
        target_name="juice-shop",
        target_version="20.1.1",
        target_commit_sha="f915bddd82790d0f3018902d36ae9b4241a5f51f",
        target_base_url=None,
        report_path="codeql.sarif",
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


def _normalize(report: dict[str, Any]):
    return normalize_codeql_report(report, _context(), normalized_at="2026-08-05T01:00:00Z")


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


def test_raw_sarif_snippets_are_not_ingested_by_v1_normalizer() -> None:
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

    assert finding["evidence"] is None
    assert finding["data_flow"] is not None
    assert finding["data_flow"][0]["source"]["content"] is None
    assert finding["data_flow"][0]["sink"]["content"] is None


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
