"""Unit tests for Human-in-the-Loop (HITL) risk evaluator and approval engine."""

from unittest.mock import patch

from src.gateway.hitl import assess_request_risk, prompt_cli_approval


def test_assess_request_risk_low() -> None:
    """Verify that benign GET and OPTIONS requests are classified as LOW risk (no approval required)."""
    res1 = assess_request_risk(method="GET", endpoint="/rest/products/search")
    assert res1["risk_level"] == "LOW"
    assert res1["requires_approval"] is False
    assert res1["risk_factors"] == []

    res2 = assess_request_risk(
        method="OPTIONS",
        endpoint="/api/Products",
        payload_category="long_string",
        burst_count=1,
    )
    assert res2["risk_level"] == "LOW"
    assert res2["requires_approval"] is False


def test_assess_request_risk_medium() -> None:
    """Verify that PUT methods and security probe payloads are classified as MEDIUM risk."""
    res_put = assess_request_risk(method="PUT", endpoint="/rest/products/1/reviews")
    assert res_put["risk_level"] == "MEDIUM"
    assert res_put["requires_approval"] is True
    assert any("PUT" in factor for factor in res_put["risk_factors"])

    res_sqli = assess_request_risk(
        method="GET",
        endpoint="/rest/products/search",
        payload_category="sql_injection_probes",
    )
    assert res_sqli["risk_level"] == "MEDIUM"
    assert res_sqli["requires_approval"] is True

    res_burst_mid = assess_request_risk(method="GET", endpoint="/api/Products", burst_count=10)
    assert res_burst_mid["risk_level"] == "MEDIUM"
    assert res_burst_mid["requires_approval"] is True


def test_assess_request_risk_high() -> None:
    """Verify that oversized payloads and burst counts > 20 are classified as HIGH risk."""
    res_oversized = assess_request_risk(
        method="GET",
        endpoint="/api/Products",
        oversized_payload=True,
    )
    assert res_oversized["risk_level"] == "HIGH"
    assert res_oversized["requires_approval"] is True
    assert any("1.5MB" in factor for factor in res_oversized["risk_factors"])

    res_burst_high = assess_request_risk(
        method="GET",
        endpoint="/api/Products",
        burst_count=25,
    )
    assert res_burst_high["risk_level"] == "HIGH"
    assert res_burst_high["requires_approval"] is True
    assert any("25 reqs" in factor for factor in res_burst_high["risk_factors"])


def test_prompt_cli_approval_auto_approve_flag() -> None:
    """Verify that auto_approve=True approves immediately."""
    assessment = assess_request_risk(method="PUT", endpoint="/rest/products/1/reviews")
    assert prompt_cli_approval(assessment, auto_approve=True) is True


def test_prompt_cli_approval_ci_mode_env(monkeypatch) -> None:
    """Verify that CI_MODE=true environment variable auto-approves."""
    monkeypatch.setenv("CI_MODE", "true")
    assessment = assess_request_risk(method="GET", endpoint="/api/Products", burst_count=25)
    assert prompt_cli_approval(assessment, auto_approve=False) is True


def test_prompt_cli_approval_user_yes(monkeypatch) -> None:
    """Verify that user entering 'y' / 'yes' returns True."""
    monkeypatch.setattr("sys.stdin.readline", lambda: "y\n")
    assessment = assess_request_risk(method="PUT", endpoint="/rest/products/1/reviews")
    assert prompt_cli_approval(assessment, auto_approve=False) is True


def test_prompt_cli_approval_user_no(monkeypatch) -> None:
    """Verify that user entering 'n' / 'no' returns False."""
    monkeypatch.setattr("sys.stdin.readline", lambda: "n\n")
    assessment = assess_request_risk(method="PUT", endpoint="/rest/products/1/reviews")
    assert prompt_cli_approval(assessment, auto_approve=False) is False


def test_prompt_cli_approval_timeout() -> None:
    """Verify that when select times out, False is returned (Default to Reject)."""
    assessment = assess_request_risk(method="PUT", endpoint="/rest/products/1/reviews")

    # Mock isatty to True and select.select to return empty list (simulating timeout)
    with patch("sys.stdin.isatty", return_value=True), patch("select.select", return_value=([], [], [])):
        result = prompt_cli_approval(assessment, auto_approve=False, timeout_seconds=0.01)
        assert result is False
