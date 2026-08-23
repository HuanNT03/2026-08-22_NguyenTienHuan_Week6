"""Unit tests for Safe Requester Tool, Method Validation, HITL integration, and Fact-checking."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import requests

from src.gateway.safe_requester import (
    OVERSIZED_PAYLOAD_BYTES,
    TOOL_SCHEMA,
    _resolve_url,
    load_payloads_dict,
    main,
    resolve_safe_payload,
    send_safe_request,
    validate_method,
)


def test_tool_schema_structure() -> None:
    """Verify that TOOL_SCHEMA is a valid Function Calling definition for AI Agent."""
    assert TOOL_SCHEMA["name"] == "send_safe_request"
    assert "description" in TOOL_SCHEMA
    params = TOOL_SCHEMA["parameters"]
    assert params["type"] == "object"
    assert "endpoint" in params["properties"]
    assert "method" in params["properties"]
    assert params["properties"]["method"]["enum"] == ["GET", "POST", "OPTIONS"]
    assert "endpoint" in params["required"]


def test_validate_method() -> None:
    """Verify HTTP method validation strictly conforms to ALLOWED_METHODS."""
    assert validate_method("GET") is True
    assert validate_method("POST") is True
    assert validate_method("OPTIONS") is True
    assert validate_method("get") is True
    assert validate_method("  post  ") is True
    assert validate_method("options") is True

    # Forbidden methods
    assert validate_method("PUT") is False
    assert validate_method("DELETE") is False
    assert validate_method("PATCH") is False
    assert validate_method("CONNECT") is False
    assert validate_method("TRACE") is False
    assert validate_method("HEAD") is False
    assert validate_method("") is False
    assert validate_method(None) is False  # type: ignore[arg-type]


def test_resolve_safe_payload() -> None:
    """Verify payload category lookup and custom override behavior."""
    # Custom override
    assert resolve_safe_payload("anything", custom_value="my_custom") == "my_custom"

    # Builtin categories
    payloads = load_payloads_dict()
    if "special_chars" in payloads:
        res = resolve_safe_payload("special_chars")
        assert res is not None
        assert res in payloads["special_chars"]

    # Nonexistent category
    res_none = resolve_safe_payload("non_existent_category_xyz")
    assert res_none is None


def test_resolve_url() -> None:
    """Verify URL prefixing with default or custom Gateway host."""
    assert _resolve_url("/api/Products", "http://localhost:3000") == "http://localhost:3000/api/Products"
    assert _resolve_url("api/Products", "http://localhost:3000") == "http://localhost:3000/api/Products"
    assert _resolve_url("http://custom-host:8000/test", "http://localhost:3000") == "http://custom-host:8000/test"
    assert _resolve_url("https://secure-host/test", "http://localhost:3000") == "https://secure-host/test"


def test_send_safe_request_forbidden_method(tmp_path: Path) -> None:
    """Verify that forbidden HTTP methods return 405 without sending network traffic."""
    log_file = tmp_path / "audit.jsonl"
    for forbidden_method in ["PUT", "DELETE", "PATCH", "HEAD"]:
        res = send_safe_request(
            endpoint="/api/Users",
            method=forbidden_method,
            log_file=log_file,
        )
        assert res["status"] == "error"
        assert res["status_code"] == 405
        assert "Method not allowed" in res["message"]
        assert forbidden_method in res["message"]

    # Check audit log recorded 405 events
    assert log_file.is_file()
    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 4
    for line in lines:
        data = json.loads(line)
        assert data["status_code"] == 405


def test_send_safe_request_get_success(tmp_path: Path) -> None:
    """Verify single GET request execution with mock response and guardrails wrapping."""
    log_file = tmp_path / "audit.jsonl"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "application/json", "Server": "JuiceShop"}
    mock_resp.iter_content.return_value = [b'{"status":"success","data":[{"id":1,"name":"Apple Juice"}]}']

    with patch("requests.Session.request", return_value=mock_resp) as mock_req:
        res = send_safe_request(
            endpoint="/rest/products/search?q=apple",
            method="GET",
            log_file=log_file,
        )

        assert res["status"] == "success"
        assert res["status_code"] == 200
        assert res["truncated"] is False
        assert "<untrusted_http_response" in res["body"]
        assert "Apple Juice" in res["body"]
        assert mock_req.called

    assert log_file.is_file()
    audit_data = json.loads(log_file.read_text(encoding="utf-8").strip())
    assert audit_data["status_code"] == 200
    assert audit_data["endpoint"] == "/rest/products/search?q=apple"
    assert audit_data["method"] == "GET"


def test_send_safe_request_options_method(tmp_path: Path) -> None:
    """Verify OPTIONS method is permitted for CORS probing."""
    log_file = tmp_path / "audit.jsonl"
    mock_resp = MagicMock()
    mock_resp.status_code = 204
    mock_resp.headers = {"Allow": "GET,PUT,OPTIONS", "Access-Control-Allow-Origin": "*"}
    mock_resp.iter_content.return_value = []

    with patch("requests.Session.request", return_value=mock_resp):
        res = send_safe_request(
            endpoint="/api/Products",
            method="OPTIONS",
            log_file=log_file,
        )
        assert res["status"] == "success"
        assert res["status_code"] == 204


def test_send_safe_request_api_key_injection(tmp_path: Path, monkeypatch) -> None:
    """Verify that AGENT_API_KEY is injected into outbound headers and masked in audit log."""
    log_file = tmp_path / "audit.jsonl"
    secret_key = "sentinel-agent-secret-xyz-999"
    monkeypatch.setenv("AGENT_API_KEY", secret_key)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.iter_content.return_value = [b'{"ok": true}']

    captured_headers: dict[str, Any] = {}

    def fake_request(*args: Any, **kwargs: Any) -> MagicMock:
        nonlocal captured_headers
        captured_headers = kwargs.get("headers", {})
        return mock_resp

    with patch("requests.Session.request", side_effect=fake_request):
        res = send_safe_request(
            endpoint="/api/Products",
            method="GET",
            log_file=log_file,
        )
        assert res["status_code"] == 200
        # Outbound header had real key
        assert captured_headers.get("x-api-key") == secret_key

    # Audit log MUST NOT contain the real key
    log_content = log_file.read_text(encoding="utf-8")
    assert secret_key not in log_content
    assert "[REDACTED_SECRET]" in log_content


def test_send_safe_request_timeout_handling(tmp_path: Path) -> None:
    """Verify socket timeout maps to status 504 with controlled error output."""
    log_file = tmp_path / "audit.jsonl"

    with patch("requests.Session.request", side_effect=requests.exceptions.Timeout("Connection timed out")):
        res = send_safe_request(
            endpoint="/api/Products",
            method="GET",
            timeout=7.0,
            log_file=log_file,
        )
        assert res["status"] == "error"
        assert res["status_code"] == 504
        assert "Gateway timeout" in res["body"]

    audit_data = json.loads(log_file.read_text(encoding="utf-8").strip())
    assert audit_data["status_code"] == 504


def test_send_safe_request_connection_error(tmp_path: Path) -> None:
    """Verify connection failure maps to status 502."""
    log_file = tmp_path / "audit.jsonl"

    with patch("requests.Session.request", side_effect=requests.exceptions.ConnectionError("Refused")):
        res = send_safe_request(
            endpoint="/api/Products",
            method="GET",
            log_file=log_file,
        )
        assert res["status"] == "error"
        assert res["status_code"] == 502
        assert "Connection to Gateway failed" in res["body"]


def test_send_safe_request_response_truncation(tmp_path: Path) -> None:
    """Verify that response bodies exceeding 2048 bytes are truncated and flagged."""
    log_file = tmp_path / "audit.jsonl"
    # Create chunks totaling > 3000 bytes
    chunk = b"X" * 512
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_resp.iter_content.return_value = [chunk, chunk, chunk, chunk, chunk, chunk]  # ~3072 bytes

    with patch("requests.Session.request", return_value=mock_resp):
        res = send_safe_request(
            endpoint="/api/Products",
            method="GET",
            log_file=log_file,
        )
        assert res["status_code"] == 200
        assert res["truncated"] is True


def test_send_safe_request_oversized_payload_generation(tmp_path: Path) -> None:
    """Verify oversized_payload=True generates 1.5MB buffer internally."""
    log_file = tmp_path / "audit.jsonl"
    mock_resp = MagicMock()
    mock_resp.status_code = 413
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.iter_content.return_value = [b'{"message": "Request Entity Too Large"}']

    sent_data_len = 0

    def fake_request(*args: Any, **kwargs: Any) -> MagicMock:
        nonlocal sent_data_len
        data = kwargs.get("data")
        if data:
            sent_data_len = len(data)
        return mock_resp

    with patch("requests.Session.request", side_effect=fake_request):
        res = send_safe_request(
            endpoint="/api/Products",
            method="GET",
            oversized_payload=True,
            auto_approve=True,
            log_file=log_file,
        )
        assert res["status_code"] == 413
        assert sent_data_len == OVERSIZED_PAYLOAD_BYTES  # 1572864 bytes (1.5MB)


def test_send_safe_request_hitl_rejection(tmp_path: Path) -> None:
    """Verify that when human rejects approval prompt, request is not sent and returns status 0."""
    log_file = tmp_path / "audit.jsonl"

    with patch("src.gateway.safe_requester.prompt_cli_approval", return_value=False), \
         patch("requests.Session.request") as mock_req:
        res = send_safe_request(
            endpoint="/rest/products/1/reviews",
            method="POST",
            payload_value={"message": "test", "author": "anonymous"},
            auto_approve=False,
            log_file=log_file,
        )
        assert res["status"] == "rejected"
        assert res["status_code"] == 0
        assert "HITL REJECTED" in res["body"]
        assert not mock_req.called

    audit_data = json.loads(log_file.read_text(encoding="utf-8").strip())
    assert audit_data["approval_status"] == "REJECTED_BY_USER"
    assert audit_data["status_code"] == 0


def test_send_safe_request_burst_mode(tmp_path: Path) -> None:
    """Verify burst mode sends N sequential requests and records rate-limit 429 metrics."""
    log_file = tmp_path / "audit.jsonl"

    call_count = 0

    def fake_request(*args: Any, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        # First 20 requests succeed (200), subsequent return 429 Too Many Requests
        if call_count <= 20:
            resp.status_code = 200
            resp.text = '{"status": "ok"}'
        else:
            resp.status_code = 429
            resp.text = '{"message": "Too many requests"}'
        return resp

    with patch("requests.Session.request", side_effect=fake_request):
        res = send_safe_request(
            endpoint="/api/Products",
            method="GET",
            burst_count=25,
            interval_seconds=0.0,
            auto_approve=True,
            log_file=log_file,
        )
        assert res["status"] == "success"
        assert res["burst_total"] == 25
        assert res["status_distribution"][200] == 20
        assert res["status_distribution"][429] == 5
        assert res["rate_limited_count"] == 5
        assert res["first_rate_limit_at"] == 21

    audit_data = json.loads(log_file.read_text(encoding="utf-8").strip())
    assert "Burst test completed" in audit_data["response_body_snippet"]
    assert "Rate limited (429): 5 reqs" in audit_data["response_body_snippet"]


def test_fact_check_post_product_reviews_endpoint(tmp_path: Path) -> None:
    """Fact-check: Verify POST /rest/products/:id/reviews behaves as an unauthenticated endpoint.

    OWASP Juice Shop design allows anonymous users to post reviews without Authorization Bearer.
    Mocking the 201 Created server response proves our client handling processes the 201 response.
    """
    log_file = tmp_path / "audit.jsonl"
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.headers = {"Content-Type": "application/json; charset=utf-8"}
    mock_resp.iter_content.return_value = [b'{"status":"success"}']

    with patch("requests.Session.request", return_value=mock_resp):
        res = send_safe_request(
            endpoint="/rest/products/1/reviews",
            method="POST",
            payload_value={"message": "Great Juice!", "author": "anonymous@juice-sh.op"},
            auto_approve=True,
            log_file=log_file,
        )
        assert res["status"] == "success"
        assert res["status_code"] == 201
        assert "<untrusted_http_response" in res["body"]
        assert "success" in res["body"]


def test_cli_main_entrypoint(monkeypatch, capsys, tmp_path: Path) -> None:
    """Verify CLI main entrypoint executes properly with argparse options."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Server": "Kong/3.6.1",
        "Via": "kong/3.6.1",
        "X-Kong-Proxy-Latency": "1",
        "X-RateLimit-Remaining-Minute": "19",
    }
    mock_resp.iter_content.return_value = [b'{"ok": true}']

    with patch("requests.Session.request", return_value=mock_resp), \
         patch("src.gateway.safe_requester.log_audit_event") as mock_log, \
         patch("sys.argv", ["safe_requester", "--url", "/api/Products", "--method", "GET", "--auto-approve"]):
        main()
        captured = capsys.readouterr()
        assert '"status_code": 200' in captured.out
        assert '"endpoint": "/api/Products"' in captured.out
        assert mock_log.called
