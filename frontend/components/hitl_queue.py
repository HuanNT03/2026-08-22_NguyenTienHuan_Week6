"""HITL Approval Queue State Manager & Interactive Sidebar Component."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

import streamlit as st


@dataclass
class HITLAction:
    """Represents a security probe action pending or resolved through HITL gate."""

    action_id: str
    endpoint: str
    method: str
    payload: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    rationale: str = ""
    created_at: float = field(default_factory=time.time)
    timeout_seconds: int = 120
    status: Literal["PENDING", "APPROVED", "REJECTED", "TIMED_OUT"] = "PENDING"
    resolved_by: str | None = None
    resolved_at: float | None = None
    rejection_reason: str | None = None

    @property
    def remaining_seconds(self) -> int:
        """Calculate remaining countdown seconds before 120s timeout."""
        elapsed = time.time() - self.created_at
        rem = int(self.timeout_seconds - elapsed)
        return max(0, rem)

    @property
    def is_expired(self) -> bool:
        """True if countdown timer reached zero."""
        return self.remaining_seconds <= 0


class HITLQueueManager:
    """Manages the in-memory lifecycle of HITL actions for Streamlit session."""

    def __init__(self) -> None:
        """Initialize empty action registry and counter."""
        self.actions: dict[str, HITLAction] = {}
        self._seq: int = 1

    def add_action(
        self,
        endpoint: str,
        method: str,
        payload: Any = None,
        headers: dict[str, str] | None = None,
        risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM",
        rationale: str = "",
        timeout_seconds: int = 120,
    ) -> str:
        """Add a new action to the pending queue and return generated action_id."""
        action_id = f"REQ-{self._seq:02d}"
        self._seq += 1
        action = HITLAction(
            action_id=action_id,
            endpoint=endpoint,
            method=method.upper(),
            payload=payload,
            headers=headers or {},
            risk_level=risk_level,
            rationale=rationale,
            timeout_seconds=timeout_seconds,
        )
        self.actions[action_id] = action
        return action_id

    def approve_action(self, action_id: str, operator: str = "security_operator") -> bool:
        """Mark an action as APPROVED."""
        if action_id not in self.actions:
            return False
        action = self.actions[action_id]
        if action.status != "PENDING":
            return False
        action.status = "APPROVED"
        action.resolved_by = operator
        action.resolved_at = time.time()
        return True

    def reject_action(self, action_id: str, reason: str = "Rejected by operator", operator: str = "security_operator") -> bool:
        """Mark an action as REJECTED."""
        if action_id not in self.actions:
            return False
        action = self.actions[action_id]
        if action.status != "PENDING":
            return False
        action.status = "REJECTED"
        action.rejection_reason = reason
        action.resolved_by = operator
        action.resolved_at = time.time()
        return True

    def check_timeouts(self) -> list[str]:
        """Check all pending actions and automatically transition expired ones to TIMED_OUT."""
        timed_out: list[str] = []
        for action_id, action in self.actions.items():
            if action.status == "PENDING" and action.is_expired:
                action.status = "TIMED_OUT"
                action.resolved_at = time.time()
                action.rejection_reason = f"Timeout ({action.timeout_seconds}s limit reached)"
                timed_out.append(action_id)
        return timed_out

    @property
    def pending_actions(self) -> list[HITLAction]:
        """Return list of currently pending actions."""
        self.check_timeouts()
        return [a for a in self.actions.values() if a.status == "PENDING"]

    @property
    def approved_actions(self) -> list[HITLAction]:
        """Return list of approved actions."""
        return [a for a in self.actions.values() if a.status == "APPROVED"]

    @property
    def rejected_actions(self) -> list[HITLAction]:
        """Return list of rejected or timed out actions."""
        return [a for a in self.actions.values() if a.status in ("REJECTED", "TIMED_OUT")]

    def get_counts(self) -> dict[str, int]:
        """Return counts of actions grouped by status."""
        self.check_timeouts()
        return {
            "pending": len(self.pending_actions),
            "approved": len(self.approved_actions),
            "rejected": len(self.rejected_actions),
            "total": len(self.actions),
        }


def get_session_hitl_manager() -> HITLQueueManager:
    """Retrieve or initialize the HITLQueueManager in Streamlit session state."""
    if "hitl_manager" not in st.session_state:
        mgr = HITLQueueManager()
        # Pre-populate sample verified items for demonstration
        mgr.add_action(
            endpoint="/rest/products/search?q=apple",
            method="GET",
            risk_level="LOW",
            rationale="Verify SQLi search filter",
        )
        mgr.approve_action("REQ-01")
        st.session_state.hitl_manager = mgr
    return st.session_state.hitl_manager


def render_hitl_sidebar(manager: HITLQueueManager | None = None) -> None:
    """Render the interactive HITL Approval Queue in the Streamlit Sidebar."""
    mgr = manager or get_session_hitl_manager()
    counts = mgr.get_counts()

    with st.sidebar:
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
                <span class="material-symbols-outlined" style="font-size: 22px; color: #4D8EFF;">gavel</span>
                <span style="font-size: 16px; font-weight: 700; color: #cdd6f4; text-transform: uppercase; letter-spacing: 0.05em;">
                    Hàng Đợi Phê Duyệt HITL
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Tab/Group 1: Pending Actions
        pending = mgr.pending_actions
        pending_badge_color = "#fab387" if pending else "#6c7086"
        st.markdown(
            f"""
            <div style="font-size: 13px; font-weight: 600; color: {pending_badge_color}; margin-top: 8px; margin-bottom: 6px;">
                ⏳ Đang chờ duyệt ({len(pending)})
            </div>
            """,
            unsafe_allow_html=True,
        )

        if not pending:
            st.caption("Không có yêu cầu nào đang chờ.")
        else:
            for act in pending:
                with st.container():
                    st.markdown(
                        f"""
                        <div style="background: rgba(30, 30, 46, 0.9); border: 1px solid rgba(250, 179, 135, 0.4); border-radius: 10px; padding: 10px; margin-bottom: 8px;">
                            <div style="display: flex; justify-content: space-between; font-size: 12px; font-weight: 700; color: #fab387;">
                                <span>#{act.action_id} | {act.method}</span>
                                <span>⏱️ {act.remaining_seconds}s</span>
                            </div>
                            <div style="font-size: 11px; color: #cdd6f4; font-family: monospace; word-break: break-all; margin: 4px 0;">
                                {act.endpoint}
                            </div>
                            <div style="font-size: 11px; color: #a6adc8;">
                                Rủi ro: <b>{act.risk_level}</b> | {act.rationale}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    col_appr, col_rej = st.columns(2)
                    with col_appr:
                        if st.button("✅ Duyệt", key=f"btn_appr_{act.action_id}", use_container_width=True):
                            mgr.approve_action(act.action_id)
                            st.rerun()
                    with col_rej:
                        if st.button("❌ Từ chối", key=f"btn_rej_{act.action_id}", use_container_width=True):
                            mgr.reject_action(act.action_id)
                            st.rerun()

        st.divider()

        # Group 2: Approved History
        approved = mgr.approved_actions
        with st.expander(f"✅ Đã xác minh & Gửi ({len(approved)})", expanded=False):
            if not approved:
                st.caption("Chưa có request nào đã duyệt.")
            for act in reversed(approved[-5:]):
                st.markdown(
                    f"""
                    <div style="font-size: 11px; color: #a6e3a1; margin-bottom: 6px; font-family: monospace;">
                        <b>{act.action_id}</b> [{act.method}] {act.endpoint}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # Group 3: Rejected / Timed out History
        rejected = mgr.rejected_actions
        with st.expander(f"🛑 Đã từ chối / Hết giờ ({len(rejected)})", expanded=False):
            if not rejected:
                st.caption("Chưa có request nào bị từ chối.")
            for act in reversed(rejected[-5:]):
                st.markdown(
                    f"""
                    <div style="font-size: 11px; color: #f38ba8; margin-bottom: 6px; font-family: monospace;">
                        <b>{act.action_id}</b> [{act.status}] {act.endpoint}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
