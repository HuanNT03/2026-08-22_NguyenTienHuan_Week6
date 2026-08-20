from pathlib import Path

import pytest

from src.normalizers.context import NormalizationContext
from src.normalizers.zap import normalize_zap_report

ROOT = Path(__file__).resolve().parents[2]


def _context(base_url: str | None = "http://juice-shop:3000") -> NormalizationContext:
    """Build a deterministic ZAP normalization context with the requested target URL."""
    return NormalizationContext(
        schema_version="2.0.0",
        normalizer_version="2.0.0",
        run_id="zap-scope-test",
        pipeline_run_id=None,
        scanned_at="2026-08-06T00:00:00Z",
        target_name="juice-shop",
        target_version="20.1.1",
        target_commit_sha="f915bddd82790d0f3018902d36ae9b4241a5f51f",
        target_base_url=base_url,
        report_path="reports/raw/zap.json",
    )


def _report(uris: list[str]) -> dict:
    """Create the smallest valid ZAP report containing one instance per supplied URI."""
    return {
        "@version": "2.17.0",
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "10000",
                        "alertRef": "10000",
                        "riskcode": "1",
                        "confidence": "2",
                        "name": "Scope fixture",
                        "instances": [{"uri": uri, "method": "GET"} for uri in uris],
                    }
                ],
            }
        ],
    }


def test_scope_filter_rejects_origin_lookalikes_and_sanitizes_warning_uris() -> None:
    report = _report(
        [
            "http://juice-shop:3000/",
            "http://juice-shop:3000/products?search=apple",
            "http://juice-shop.evil.example:3000/path?token=secret#fragment",
            "http://juice-shop:3000@evil.example/path?api_key=secret",
            "https://juice-shop:3000/path",
            "http://juice-shop/path",
            "https://user:password@evil.example:8443/path?token=secret&empty=&token=again#fragment",
        ]
    )

    result = normalize_zap_report(report, _context(), normalized_at="2026-08-06T01:00:00Z")

    assert len(result.findings) == 2
    assert result.warnings["out_of_scope_instances_filtered"] == 5
    assert result.warnings["out_of_scope_uris"] == [
        "http://evil.example/path?api_key",
        "http://juice-shop.evil.example:3000/path?token",
        "http://juice-shop/path",
        "https://evil.example:8443/path?empty&token",
        "https://juice-shop:3000/path",
    ]
    warning_text = "\n".join(result.warnings["out_of_scope_uris"])
    assert "secret" not in warning_text
    assert "password" not in warning_text
    assert "fragment" not in warning_text


@pytest.mark.parametrize("base_url", [None, "", "juice-shop:3000", "ftp://juice-shop:3000"])
def test_scope_filter_fails_closed_for_invalid_target_base_url(base_url: str | None) -> None:
    with pytest.raises(ValueError, match="target base URL"):
        normalize_zap_report(_report(["http://juice-shop:3000/"]), _context(base_url))


def test_scope_warning_uri_list_is_deterministic_and_bounded() -> None:
    external_uris = [f"https://external.example/path/{index}?token=value-{index}" for index in range(101)]
    result = normalize_zap_report(
        _report(["http://juice-shop:3000/", *reversed(external_uris)]),
        _context(),
        normalized_at="2026-08-06T01:00:00Z",
    )

    assert result.warnings["out_of_scope_instances_filtered"] == 101
    assert result.warnings["out_of_scope_unique_uri_count"] == 101
    assert len(result.warnings["out_of_scope_uris"]) == 100
    assert result.warnings["out_of_scope_uris"] == sorted(result.warnings["out_of_scope_uris"])
    assert result.warnings["out_of_scope_uris_truncated"] is True
