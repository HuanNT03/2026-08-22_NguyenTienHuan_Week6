"""Integration tests verifying Mock Server DAST crawlability and ZAP compatibility."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

# Add api-server directory to sys.path for import
API_SERVER_DIR = Path(__file__).resolve().parents[2] / "api-server"
if str(API_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(API_SERVER_DIR))

from mock_server import run_mock_server_context


def test_mock_server_crawlable_html_and_login() -> None:
    """Verify that Mock Server provides HTML crawlable links and mock JWT login for ZAP."""
    with run_mock_server_context(host="127.0.0.1", port=38501) as base_url:
        # 1. Check HTML index for Spider crawling
        req_html = urllib.request.Request(f"{base_url}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req_html) as resp:
            assert resp.status == 200
            html_body = resp.read().decode("utf-8")
            assert "<!DOCTYPE html>" in html_body
            assert "/api/vulnerable/search?q=juice" in html_body
            assert "/api/vulnerable/user/profile?id=1" in html_body
            assert "/api/vulnerable/env-config" in html_body
            assert 'action="/api/vulnerable/feedback"' in html_body

        # 2. Check JSON index
        req_json = urllib.request.Request(f"{base_url}/", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req_json) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "online"
            assert "v20.1.1-mock" in data["version"]

        # 3. Check health and version endpoints
        with urllib.request.urlopen(f"{base_url}/health") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "online"

        with urllib.request.urlopen(f"{base_url}/rest/admin/application-version") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["version"] == "20.1.1"

        # 4. Check POST /rest/user/login for ZAP Authentication Job
        login_payload = json.dumps({"email": "user@juice-sh.op", "password": "user123"}).encode("utf-8")
        req_login = urllib.request.Request(
            f"{base_url}/rest/user/login",
            data=login_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_login) as resp:
            assert resp.status == 200
            login_data = json.loads(resp.read().decode("utf-8"))
            assert login_data["status"] == "success"
            assert "token" in login_data["data"]
            assert login_data["data"]["umail"] == "user@juice-sh.op"


def test_mock_server_vulnerable_endpoints_behavior() -> None:
    """Verify that Mock Server exposes all intended vulnerabilities for DAST detection."""
    with run_mock_server_context(host="127.0.0.1", port=38502) as base_url:
        # SQL Injection trigger returns 500 with leaked error
        try:
            import urllib.parse
            q_val = urllib.parse.quote("' OR 1=1--")
            req_sqli = urllib.request.Request(f"{base_url}/api/vulnerable/search?q={q_val}")
            urllib.request.urlopen(req_sqli)
            pytest.fail("Expected HTTP 500 error for SQLi probe")
        except urllib.error.HTTPError as err:
            assert err.code == 500
            body = json.loads(err.read().decode("utf-8"))
            assert body["status"] == "error"
            assert "SQL syntax error" in body["sql_error"]
            assert "admin.security@sentinel.internal" in body["sql_error"]

        # Information exposure & stacktrace leak
        with urllib.request.urlopen(f"{base_url}/api/vulnerable/user/profile?id=1") as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
            assert body["status"] == "success"
            assert "Exception in thread" in body["debug_stacktrace"]
            assert "postgres://" in body["debug_stacktrace"]

        # Cleartext secrets in environment config
        with urllib.request.urlopen(f"{base_url}/api/vulnerable/env-config") as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
            assert "secrets" in body
            assert "sk-proj-" in body["secrets"]["openai_api_key"]

        # Customer feedback POST submission
        feedback_payload = b"comment=Excellent+service"
        req_fb = urllib.request.Request(
            f"{base_url}/api/vulnerable/feedback",
            data=feedback_payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req_fb) as resp:
            assert resp.status == 201
            body = json.loads(resp.read().decode("utf-8"))
            assert body["status"] == "created"
