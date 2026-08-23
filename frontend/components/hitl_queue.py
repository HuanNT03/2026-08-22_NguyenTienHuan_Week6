"""HITL Approval Queue State Manager & Interactive Sidebar Component.

Quản lý hàng đợi phê duyệt Human-In-The-Loop cho Project Sentinel Streamlit Dashboard.
Chuẩn hóa 100% bằng Google Material Symbols Outlined, loại bỏ hoàn toàn ký tự emoji.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

import streamlit as st


@dataclass
class HITLAction:
    """Đại diện cho một hành động kiểm thử bảo mật đang chờ hoặc đã được xử lý qua chốt chặn HITL.

    Attributes:
        action_id: Mã định danh hành động (vd: 'REQ-01').
        endpoint: Endpoint HTTP kiểm thử (vd: '/rest/products/search?q=apple').
        method: Phương thức HTTP ('GET', 'PUT', 'OPTIONS').
        payload: Dữ liệu payload gửi kèm (nếu có).
        headers: Các HTTP header tùy chỉnh.
        risk_level: Mức độ rủi ro ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        rationale: Lý do thực hiện kiểm thử.
        created_at: Thời điểm tạo yêu cầu (timestamp unix epoch).
        timeout_seconds: Thời gian chờ tối đa bằng giây (mặc định 120s).
        status: Trạng thái hiện tại ('PENDING', 'APPROVED', 'REJECTED', 'TIMED_OUT').
        resolved_by: Tên người/hệ thống đã đưa ra quyết định duyệt/từ chối.
        resolved_at: Thời điểm xử lý quyết định.
        rejection_reason: Lý do từ chối nếu bị hủy.
    """

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
        """Tính toán số giây còn lại trước khi hết hạn 120s timeout."""
        elapsed = time.time() - self.created_at
        rem = int(self.timeout_seconds - elapsed)
        return max(0, rem)

    @property
    def is_expired(self) -> bool:
        """Trả về True nếu bộ đếm ngược đã về 0."""
        return self.remaining_seconds <= 0


class HITLQueueManager:
    """Quản lý vòng đời trong bộ nhớ của các hành động HITL trong Streamlit session."""

    def __init__(self) -> None:
        """Khởi tạo danh sách rỗng các action và bộ đếm tuần tự."""
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
        """Thêm một hành động mới vào hàng đợi chờ duyệt và trả về mã action_id được sinh ra.

        Args:
            endpoint: Endpoint HTTP cần thăm dò.
            method: Phương thức HTTP ('GET', 'POST', 'OPTIONS').
            payload: Payload dữ liệu gửi kèm nếu có.
            headers: Headers HTTP bổ sung.
            risk_level: Mức độ rủi ro đánh giá ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
            rationale: Lý do và căn cứ kiểm thử an ninh.
            timeout_seconds: Thời gian hết hạn (mặc định 120s).

        Returns:
            str: Mã định danh hành động (vd: 'REQ-01', 'REQ-02').
        """
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
        """Đánh dấu hành động là APPROVED (Phê duyệt).

        Args:
            action_id: Mã hành động cần duyệt.
            operator: Tên định danh chuyên viên phê duyệt.

        Returns:
            bool: True nếu chuyển trạng thái thành công, False nếu mã không tồn tại hoặc không ở trạng thái PENDING.
        """
        if action_id not in self.actions:
            return False
        action = self.actions[action_id]
        if action.status != "PENDING":
            return False
        action.status = "APPROVED"
        action.resolved_by = operator
        action.resolved_at = time.time()
        return True

    def reject_action(
        self,
        action_id: str,
        reason: str = "Rejected by operator",
        operator: str = "security_operator",
    ) -> bool:
        """Đánh dấu hành động là REJECTED (Từ chối).

        Args:
            action_id: Mã hành động cần từ chối.
            operator: Tên định danh chuyên viên từ chối.
            reason: Lý do từ chối.

        Returns:
            bool: True nếu chuyển trạng thái thành công, False nếu mã không tồn tại hoặc không ở trạng thái PENDING.
        """
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

    def record_rejected_action(
        self,
        endpoint: str,
        method: str,
        payload: Any = None,
        headers: dict[str, str] | None = None,
        risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM",
        rationale: str = "",
        reason: str = "Tự động chặn bởi chính sách HITL (cần phê duyệt thủ công)",
    ) -> str:
        """Ghi nhận một hành động bị chặn trực tiếp từ Agent vào danh sách đã từ chối."""
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
            status="REJECTED",
            resolved_by="hitl_policy_gate",
            resolved_at=time.time(),
            rejection_reason=reason,
        )
        self.actions[action_id] = action
        return action_id

    def check_timeouts(self) -> list[str]:
        """Quét và tự động chuyển các hành động quá hạn 120s sang trạng thái TIMED_OUT.

        Returns:
            list[str]: Danh sách các action_id vừa bị chuyển sang TIMED_OUT.
        """
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
        """Trả về danh sách các hành động đang ở trạng thái PENDING."""
        self.check_timeouts()
        return [a for a in self.actions.values() if a.status == "PENDING"]

    @property
    def approved_actions(self) -> list[HITLAction]:
        """Trả về danh sách các hành động đã được APPROVED."""
        return [a for a in self.actions.values() if a.status == "APPROVED"]

    @property
    def rejected_actions(self) -> list[HITLAction]:
        """Trả về danh sách các hành động bị REJECTED hoặc TIMED_OUT."""
        return [a for a in self.actions.values() if a.status in ("REJECTED", "TIMED_OUT")]

    def get_counts(self) -> dict[str, int]:
        """Trả về thống kê số lượng hành động theo từng nhóm trạng thái.

        Returns:
            dict[str, int]: Dictionary với các keys 'pending', 'approved', 'rejected', 'total'.
        """
        self.check_timeouts()
        return {
            "pending": len(self.pending_actions),
            "approved": len(self.approved_actions),
            "rejected": len(self.rejected_actions),
            "total": len(self.actions),
        }


def get_session_hitl_manager() -> HITLQueueManager:
    """Truy xuất hoặc khởi tạo đối tượng HITLQueueManager trong Streamlit session_state."""
    if "hitl_manager" not in st.session_state:
        mgr = HITLQueueManager()
        # Seed initial demonstrated verified item
        mgr.add_action(
            endpoint="/rest/products/search?q=apple",
            method="GET",
            risk_level="LOW",
            rationale="Verify SQLi search filter probe",
        )
        mgr.approve_action("REQ-01")
        st.session_state.hitl_manager = mgr
    return st.session_state.hitl_manager


def render_hitl_sidebar(manager: HITLQueueManager | None = None) -> None:
    """Hiển thị Hàng Đợi Phê Duyệt HITL trên Sidebar Streamlit theo chuẩn Bento Box + Material Symbols."""
    mgr = manager or get_session_hitl_manager()

    with st.sidebar:
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 14px; padding-bottom: 10px; border-bottom: 1px solid rgba(255,255,255,0.08);">
                <span class="material-symbols-outlined" style="font-size: 22px; color: #3B82F6;">gavel</span>
                <span style="font-size: 14px; font-weight: 700; color: #cdd6f4; text-transform: uppercase; letter-spacing: 0.05em;">
                    HÀNG ĐỢI PHÊ DUYỆT (HITL)
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Nhóm 1: Yêu cầu Đang chờ duyệt (Pending Actions)
        pending = mgr.pending_actions
        pending_badge_color = "#fab387" if pending else "#6c7086"
        st.markdown(
            f"""
            <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 6px; margin-bottom: 8px;">
                <span style="font-size: 13px; font-weight: 600; color: {pending_badge_color}; display: flex; align-items: center; gap: 6px;">
                    <span class="material-symbols-outlined" style="font-size: 16px;">schedule</span> Đang chờ duyệt
                </span>
                <span class="bento-badge {'high' if pending else 'default'}">{len(pending)}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if not pending:
            st.caption("Không có yêu cầu nào đang chờ xử lý.")
        else:
            for act in pending:
                risk_variant = {
                    "LOW": "low",
                    "MEDIUM": "medium",
                    "HIGH": "high",
                    "CRITICAL": "critical",
                }.get(act.risk_level, "info")

                with st.container():
                    st.markdown(
                        f"""
                        <div style="background: rgba(17, 25, 39, 0.95); border: 1px solid rgba(250, 179, 135, 0.35); border-radius: 12px; padding: 12px; margin-bottom: 10px; box-shadow: 0 4px 16px rgba(0,0,0,0.3);">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                <span style="font-size: 12px; font-weight: 700; color: #fab387;">#{act.action_id} | {act.method}</span>
                                <span class="bento-badge default"><span class="material-symbols-outlined" style="font-size: 12px;">timer</span> {act.remaining_seconds}s</span>
                            </div>
                            <div style="font-size: 11px; color: #cdd6f4; font-family: monospace; word-break: break-all; margin-bottom: 6px; background: rgba(0,0,0,0.25); padding: 4px 8px; border-radius: 6px;">
                                {act.endpoint}
                            </div>
                            <div style="display: flex; align-items: center; justify-content: space-between; font-size: 11px; color: #a6adc8;">
                                <span>Rủi ro: <span class="bento-badge {risk_variant}">{act.risk_level}</span></span>
                            </div>
                            <div style="font-size: 11px; color: #6c7086; margin-top: 4px;">
                                {act.rationale}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    col_appr, col_rej = st.columns(2)
                    with col_appr:
                        if st.button("Phê duyệt", key=f"btn_appr_{act.action_id}", type="primary", use_container_width=True):
                            mgr.approve_action(act.action_id)
                            try:
                                from src.gateway.safe_requester import send_safe_request
                                probe_res = send_safe_request(
                                    endpoint=act.endpoint,
                                    method=act.method,
                                    payload_value=act.payload,
                                    headers=act.headers,
                                    auto_approve=True,
                                )
                                st.session_state.last_probe_response = probe_res
                                st.toast(f"Đã duyệt và gửi thành công #{act.action_id} (HTTP {probe_res.get('status_code')})!")
                            except Exception as err:
                                st.toast(f"Lỗi khi gửi request: {err}")
                            st.rerun()
                    with col_rej:
                        if st.button("Từ chối", key=f"btn_rej_{act.action_id}", use_container_width=True):
                            mgr.reject_action(act.action_id)
                            st.toast(f"Đã từ chối #{act.action_id}")
                            st.rerun()

        st.divider()

        # Nhóm 2: Yêu cầu Đã xác minh (Approved History)
        approved = mgr.approved_actions
        with st.expander(f"Đã xác minh ({len(approved)})", expanded=False):
            if not approved:
                st.caption("Chưa có request nào được phê duyệt.")
            for act in reversed(approved[-5:]):
                st.markdown(
                    f"""
                    <div style="font-size: 11px; color: #a6e3a1; margin-bottom: 6px; font-family: monospace; background: rgba(166, 227, 161, 0.08); padding: 6px 8px; border-radius: 6px; border: 1px solid rgba(166, 227, 161, 0.2);">
                        <span style="font-weight: 700;">#{act.action_id}</span> [{act.method}] {act.endpoint}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # Nhóm 3: Yêu cầu Đã từ chối / Hết giờ (Rejected History)
        rejected = mgr.rejected_actions
        with st.expander(f"Đã từ chối / Hết giờ ({len(rejected)})", expanded=False):
            if not rejected:
                st.caption("Chưa có request nào bị từ chối.")
            for act in reversed(rejected[-5:]):
                st.markdown(
                    f"""
                    <div style="font-size: 11px; color: #f38ba8; margin-bottom: 6px; font-family: monospace; background: rgba(243, 139, 168, 0.08); padding: 6px 8px; border-radius: 6px; border: 1px solid rgba(243, 139, 168, 0.2);">
                        <span style="font-weight: 700;">#{act.action_id}</span> [{act.status}] {act.endpoint}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
