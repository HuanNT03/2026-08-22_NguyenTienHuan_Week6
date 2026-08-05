import pytest

from src.normalizers.context import NormalizationContext
from src.normalizers.zap import _request_excerpt, normalize_zap_report


def _context() -> NormalizationContext:
    return NormalizationContext(
        schema_version="2.0.0",
        normalizer_version="2.0.0",
        run_id="zap-unit",
        pipeline_run_id=None,
        scanned_at="2026-08-05T00:00:00Z",
        target_name="juice-shop",
        target_version="20.1.1",
        target_commit_sha="f915bddd82790d0f3018902d36ae9b4241a5f51f",
        target_base_url="http://juice-shop:3000",
        report_path="reports/raw/zap.json",
    )


def _normalize(instance: dict, alert_otherinfo=None):
    alert = {
        "pluginid": "10000",
        "alertRef": "10000-1",
        "riskcode": "1",
        "confidence": "2",
        "name": "Test alert",
        "instances": [instance],
    }
    if alert_otherinfo is not None:
        alert["otherinfo"] = alert_otherinfo
    report = {"@version": "2.17.0", "site": [{"alerts": [alert]}]}
    return normalize_zap_report(report, _context(), normalized_at="2026-08-05T01:00:00Z").findings[0]


@pytest.mark.parametrize(
    ("method", "uri", "parameter", "expected"),
    [
        ("GET", "http://juice-shop:3000/search", "q", "GET http://juice-shop:3000/search (param: q)"),
        (None, "http://juice-shop:3000/search", None, "http://juice-shop:3000/search"),
        ("POST", None, None, "POST"),
        (None, None, None, None),
    ],
)
def test_request_excerpt_uses_only_present_values(method, uri, parameter, expected) -> None:
    assert _request_excerpt(method, uri, parameter) == expected


def test_zap_direct_http_evidence_mapping() -> None:
    finding = _normalize({
        "uri": "http://juice-shop:3000/search",
        "method": "get",
        "param": "q",
        "evidence": "matched header",
        "otherinfo": "instance note",
        "attack": "payload",
    })
    evidence = finding["evidence"]

    assert evidence["quality"] == "direct"
    assert evidence["provenance"] == "zap.json:site[0].alerts[0].instances[0]"
    assert evidence["http_evidence"] == {
        "request_excerpt": "GET http://juice-shop:3000/search (param: q)",
        "matched_evidence": "matched header",
        "context_note": "instance note",
        "attack_payload": "payload",
        "redacted": False,
        "truncated": False,
    }


def test_zap_context_note_is_inferred_and_alert_value_is_fallback() -> None:
    finding = _normalize(
        {"uri": "http://juice-shop:3000/", "method": "GET", "evidence": "", "attack": "payload"},
        alert_otherinfo="alert note",
    )

    assert finding["evidence"]["quality"] == "inferred"
    assert finding["evidence"]["http_evidence"]["context_note"] == "alert note"


def test_attack_payload_alone_does_not_raise_quality() -> None:
    finding = _normalize({"uri": "http://juice-shop:3000/", "method": "GET", "attack": "payload"})

    assert finding["evidence"]["quality"] == "none"
