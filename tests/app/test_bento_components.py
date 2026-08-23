"""Unit tests for Bento Box components, Material Symbols renderers, and HITL Queue."""

from frontend.components.bento import (
    build_guardrails_kpi_grid_html,
    build_realtime_log_box_html,
    build_security_badge_html,
    format_material_icon,
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
