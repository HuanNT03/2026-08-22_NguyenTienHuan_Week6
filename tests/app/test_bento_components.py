import pytest
import streamlit as st

from frontend.components.bento import (
    build_guardrails_kpi_grid_html,
    build_realtime_log_box_html,
    build_security_badge_html,
    format_material_icon,
    render_agent_span_card,
    render_clean_html,
    render_gateway_audit_card,
)
from frontend.components.hitl_queue import HITLQueueManager


def test_format_material_icon() -> None:
    """Verify material icon HTML generation."""
    html = format_material_icon("shield", size=24, color="#4EDEA3")
    assert 'class="material-symbols-outlined"' in html
    assert ">shield</span>" in html
    assert "font-size: 24px" in html
    assert "color: #4EDEA3" in html


def test_build_security_badge_html() -> None:
    """Verify security badge HTML formatting with variants."""
    badge_html = build_security_badge_html("CRITICAL", variant="critical", icon="gpp_bad")
    assert "bento-badge critical" in badge_html
    assert "CRITICAL" in badge_html
    assert "gpp_bad" in badge_html


def test_build_realtime_log_box_html() -> None:
    """Verify streaming log box HTML generation with max height and scroll behavior."""
    log_text = "Line 1: Scanning started\nLine 2: Semgrep rule match\nLine 3: Complete"
    html = build_realtime_log_box_html(log_text, max_height="120px")
    assert "bento-terminal-box" in html
    assert "max-height: 120px" in html
    assert "Line 2: Semgrep rule match" in html
    assert "overflow-y: auto" in html


def test_build_guardrails_kpi_grid_html() -> None:
    """Verify Guardrails KPI grid generation with all 4 metrics."""
    html = build_guardrails_kpi_grid_html(
        pii_count=14,
        injection_count=3,
        approved_count=8,
        rejected_count=2,
        mean_latency_ms=124.5,
        total_groups=5,
        confirmed_tp=4,
        false_positives=1,
    )
    assert "PII Masked" in html
    assert "14" in html
    assert "Injections Neutralized" in html
    assert "3" in html
    assert "HITL Decisions" in html
    assert "124.5ms" in html
    assert "material-symbols-outlined" in html


def test_hitl_queue_manager_lifecycle() -> None:
    """Verify adding, approving, rejecting, and timeout handling in HITLQueueManager."""
    mgr = HITLQueueManager()

    # 1. Add pending action
    action_id = mgr.add_action(
        endpoint="/rest/products/1/reviews",
        method="POST",
        payload={"message": "Test review"},
        risk_level="MEDIUM",
        rationale="Probe POST mutation on reviews",
        timeout_seconds=120,
    )
    assert action_id.startswith("REQ-")
    assert len(mgr.pending_actions) == 1
    assert mgr.get_counts()["pending"] == 1

    # 2. Approve action
    approved = mgr.approve_action(action_id, operator="sec_engineer")
    assert approved is True
    assert len(mgr.pending_actions) == 0
    assert len(mgr.approved_actions) == 1
    assert mgr.get_counts()["approved"] == 1

    # 3. Add second action and reject
    action_id_2 = mgr.add_action(
        endpoint="/api/Users",
        method="GET",
        risk_level="HIGH",
        rationale="Probe unauthorized user list",
    )
    rejected = mgr.reject_action(action_id_2, reason="Dangerous route")
    assert rejected is True
    assert len(mgr.rejected_actions) == 1
    assert mgr.get_counts()["rejected"] == 1


def test_hitl_queue_manager_timeout_expiry() -> None:
    """Verify that actions past timeout threshold transition to TIMED_OUT."""
    mgr = HITLQueueManager()
    action_id = mgr.add_action(
        endpoint="/api/test",
        method="GET",
        timeout_seconds=1,  # 1 second timeout for testing
    )

    # Manually backdate created_at to trigger timeout
    mgr.actions[action_id].created_at -= 5

    timed_out_ids = mgr.check_timeouts()
    assert action_id in timed_out_ids
    assert mgr.actions[action_id].status == "TIMED_OUT"
    assert len(mgr.pending_actions) == 0
    assert len(mgr.rejected_actions) == 1


def test_hitl_queue_manager_record_rejected_action() -> None:
    """Verify directly recording rejected actions from Agent execution."""
    mgr = HITLQueueManager()
    action_id = mgr.record_rejected_action(
        endpoint="/rest/user/login",
        method="POST",
        payload={"email": "admin@juice-sh.op"},
        risk_level="MEDIUM",
        rationale="Agent ReAct Probe",
        reason="Chốt chặn HITL: Tự động chặn trong phiên Agent",
    )
    assert action_id.startswith("REQ-")
    assert len(mgr.rejected_actions) == 1
    assert mgr.actions[action_id].status == "REJECTED"
    assert mgr.actions[action_id].rejection_reason == "Chốt chặn HITL: Tự động chặn trong phiên Agent"


def test_hitl_queue_manager_in_flight_approval_multithreaded() -> None:
    """Verify thread-safe in-flight approval pause and wake-up via approval."""
    import threading
    import time

    mgr = HITLQueueManager()
    result_container: dict[str, bool] = {}

    def agent_worker() -> None:
        assessment = {
            "endpoint": "/rest/user/login",
            "method": "POST",
            "payload": {"email": "admin@juice-sh.op"},
            "risk_level": "MEDIUM",
            "purpose": "Test SQLi login bypass",
        }
        res = mgr.request_in_flight_approval(assessment, timeout_seconds=5)
        result_container["decision"] = res

    # Start agent thread that will pause in request_in_flight_approval
    t = threading.Thread(target=agent_worker, daemon=True)
    t.start()

    # Allow worker to register pending action
    time.sleep(0.1)
    pending = mgr.pending_actions
    assert len(pending) == 1
    action_id = pending[0].action_id

    # Approve action from UI thread
    approved = mgr.approve_action(action_id, operator="sec_operator")
    assert approved is True

    # Wait for agent thread to finish
    t.join(timeout=2.0)
    assert not t.is_alive()
    assert result_container.get("decision") is True
    assert mgr.actions[action_id].status == "APPROVED"


def test_hitl_queue_manager_in_flight_rejection_multithreaded() -> None:
    """Verify thread-safe in-flight rejection pause and wake-up via rejection."""
    import threading
    import time

    mgr = HITLQueueManager()
    result_container: dict[str, bool] = {}

    def agent_worker() -> None:
        assessment = {
            "endpoint": "/api/vulnerable/feedback",
            "method": "POST",
            "risk_level": "HIGH",
            "purpose": "Test feedback mutation",
        }
        res = mgr.request_in_flight_approval(assessment, timeout_seconds=5)
        result_container["decision"] = res

    t = threading.Thread(target=agent_worker, daemon=True)
    t.start()

    time.sleep(0.1)
    pending = mgr.pending_actions
    assert len(pending) == 1
    action_id = pending[0].action_id

    # Reject action from UI thread
    rejected = mgr.reject_action(action_id, reason="Unsafe endpoint")
    assert rejected is True

    t.join(timeout=2.0)
    assert not t.is_alive()
    assert result_container.get("decision") is False
    assert mgr.actions[action_id].status == "REJECTED"


def test_hitl_queue_manager_in_flight_timeout() -> None:
    """Verify in-flight approval fails safely with timeout if no approval occurs."""
    mgr = HITLQueueManager()
    assessment = {
        "endpoint": "/api/timeout-test",
        "method": "POST",
        "risk_level": "MEDIUM",
    }
    # Short timeout for testing
    res = mgr.request_in_flight_approval(assessment, timeout_seconds=0.2)
    assert res is False
    assert len(mgr.rejected_actions) == 1
    assert mgr.rejected_actions[0].status == "TIMED_OUT"


def test_render_clean_html_behavior(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify render_clean_html strips leading whitespace on every line and calls st.markdown."""
    captured_html = []

    def mock_markdown(content: str, unsafe_allow_html: bool = False) -> None:
        captured_html.append((content, unsafe_allow_html))

    monkeypatch.setattr(st, "markdown", mock_markdown)

    sample_html = """
        <div style="padding: 10px;">
            <span>Nested content</span>
        </div>
    """
    render_clean_html(sample_html)

    assert len(captured_html) == 1
    rendered_text, allow_html = captured_html[0]
    assert allow_html is True
    assert '<div style="padding: 10px;"><span>Nested content</span></div>' in rendered_text
    assert "    <div" not in rendered_text


def test_render_agent_span_card_behavior(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify render_agent_span_card formats badges, error alerts, and tokens correctly."""
    captured_html = []

    def mock_markdown(content: str, unsafe_allow_html: bool = False) -> None:
        captured_html.append(content)

    monkeypatch.setattr(st, "markdown", mock_markdown)

    span = {
        "step_index": 2,
        "run_type": "tool",
        "name": "lookup_safe_payloads",
        "status": "error",
        "duration_ms": 142.5,
        "group_id": "GRP-01",
        "start_time": "2026-08-24T14:00:00Z",
        "token_usage": {
            "prompt_tokens": 120,
            "completion_tokens": 45,
            "total_tokens": 165,
        },
        "inputs": {"category": "sqli"},
        "outputs": {"results": []},
        "error": {
            "error_type": "ConnectionTimeout",
            "message": "Gateway timed out after 7.0s",
        },
    }

    render_agent_span_card(span)

    assert len(captured_html) >= 1
    html_output = captured_html[0]
    assert "TOOL" in html_output
    assert "lookup_safe_payloads" in html_output
    assert "ERROR" in html_output
    assert "165" in html_output
    assert "Prompt: 120" in html_output
    assert "ConnectionTimeout" in html_output
    assert "Gateway timed out" in html_output


def test_render_gateway_audit_card_behavior(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify render_gateway_audit_card formats HTTP status, PII tags, and injection alerts."""
    captured_html = []

    def mock_markdown(content: str, unsafe_allow_html: bool = False) -> None:
        captured_html.append(content)

    monkeypatch.setattr(st, "markdown", mock_markdown)

    rec = {
        "method": "POST",
        "endpoint": "/rest/user/login",
        "status_code": 200,
        "duration_ms": 88.4,
        "approval_status": "AUTO_APPROVED",
        "timestamp": "2026-08-24T14:05:00Z",
        "guardrails": {
            "redaction_applied": True,
            "redaction_count": 2,
            "redacted_types": ["EMAIL", "PASSWORD"],
            "prompt_injection_detected": True,
            "prompt_injection_risk": "SUSPICIOUS_INJECTION_DETECTED",
        },
        "request_headers": {"Content-Type": "application/json"},
        "response_headers": {"Set-Cookie": "[REDACTED]"},
        "response_body_snippet": '{"token": "[REDACTED]"}',
    }

    render_gateway_audit_card(rec)

    assert len(captured_html) >= 1
    html_output = captured_html[0]
    assert "POST" in html_output
    assert "/rest/user/login" in html_output
    assert "HTTP 200" in html_output
    assert "AUTO_APPROVED" in html_output
    assert "EMAIL" in html_output
    assert "PASSWORD" in html_output
    assert "Prompt Injection" in html_output


