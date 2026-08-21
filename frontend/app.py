"""Project Sentinel - DevSecOps & Security AI Analysis Dashboard Entrypoint."""

import os
import sys
import urllib.request
from pathlib import Path

# Ensure project root is in sys.path for Streamlit execution
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st

from frontend.components.bento import inject_bento_css, render_bento_card, render_bento_header

st.set_page_config(
    page_title="Project Sentinel - Security Operations Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject custom CSS for Bento Box layout
inject_bento_css()

# Header Section
st.markdown(
    """
    <div style="background: linear-gradient(135deg, rgba(30, 30, 46, 0.9) 0%, rgba(24, 24, 37, 0.9) 100%); padding: 24px 28px; border-radius: 20px; border: 1px solid rgba(205, 214, 244, 0.1); margin-bottom: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
        <div style="display: flex; align-items: center; gap: 16px;">
            <div style="font-size: 40px; background: rgba(203, 166, 247, 0.15); padding: 12px; border-radius: 16px; border: 1px solid rgba(203, 166, 247, 0.3);">🛡️</div>
            <div>
                <h1 style="margin: 0; font-size: 30px; font-weight: 800; background: linear-gradient(90deg, #cdd6f4, #cba6f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Project Sentinel</h1>
                <p style="margin: 4px 0 0 0; color: #a6adc8; font-size: 14px;">DevSecOps Operations & Security AI Analysis Dashboard — OWASP Juice Shop Target</p>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Check Juice Shop target status
target_port = os.getenv("JUICE_SHOP_PORT", "3000")
target_url = f"http://localhost:{target_port}/"

is_target_online = False
try:
    with urllib.request.urlopen(target_url, timeout=2) as response:
        if response.status in (200, 302, 301):
            is_target_online = True
except Exception:  # noqa: BLE001
    is_target_online = False

render_bento_header("Hệ thống Overview (Bento Box Grid)", "Theo dõi trạng thái môi trường và pipeline tự động", icon="⚡")

# Bento Grid Top Metrics (4 Columns)
col1, col2, col3, col4 = st.columns(4)

with col1:
    status_str = "🟢 Online" if is_target_online else "🔴 Offline"
    badge_variant = "success" if is_target_online else "critical"
    render_bento_card(
        title="Target App (Juice Shop)",
        value=status_str,
        description=f"Local Host Port: {target_port}",
        icon="🎯",
        badge_text="Target Lock",
        badge_variant=badge_variant,
    )

with col2:
    render_bento_card(
        title="Knowledge Base",
        value="442+ Docs",
        description="SQLite FTS5 Search Engine",
        icon="📚",
        badge_text="Canonical KB",
        badge_variant="info",
    )

with col3:
    render_bento_card(
        title="Normalizer Pipeline",
        value="Unified Findings",
        description="Semgrep, CodeQL, ZAP DAST",
        icon="🔄",
        badge_text="JSONL Schema v2",
        badge_variant="low",
    )

with col4:
    render_bento_card(
        title="AI Security Agent",
        value="Week 3 Active",
        description="Redaction + KB Provenance",
        icon="🤖",
        badge_text="Qwen LLM",
        badge_variant="success",
    )

st.divider()

render_bento_header("Bento Quick Navigation & Guidance", "Lựa chọn các phân vùng chức năng trên thanh Sidebar bên trái", icon="🧭")

# Bento Cards Grid for Navigation Features (3 Columns)
ca, cb, cc = st.columns(3)

with ca:
    st.markdown(
        """
        <div class="bento-card">
            <div class="bento-icon">🚀</div>
            <div class="bento-title">1. Scan & Normalize</div>
            <div style="color: #cdd6f4; font-size: 15px; font-weight: 600; margin-bottom: 8px;">Quét & Chuẩn hóa Lỗ hổng</div>
            <ul style="color: #a6adc8; font-size: 13px; padding-left: 18px; margin-bottom: 0;">
                <li>Khởi động bài quét SAST (Semgrep, CodeQL)</li>
                <li>Khởi động DAST (Baseline, Full Scan, DAST Admin)</li>
                <li>Tải lên & chọn file raw dạng checkbox (Select All)</li>
                <li>Chuẩn hóa về Unified Findings JSONL</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

with cb:
    st.markdown(
        """
        <div class="bento-card">
            <div class="bento-icon">📚</div>
            <div class="bento-title">2. Knowledge Base</div>
            <div style="color: #cdd6f4; font-size: 15px; font-weight: 600; margin-bottom: 8px;">Tra cứu Tri thức An ninh Mạng</div>
            <ul style="color: #a6adc8; font-size: 13px; padding-left: 18px; margin-bottom: 0;">
                <li>Tìm kiếm từ khóa FTS5 trên 442+ canonical docs</li>
                <li>Truy vấn mã lỗ hổng CWE & OWASP Top 10</li>
                <li>Xem hướng dẫn khắc phục (Remediation)</li>
                <li>Trích dẫn nguồn chuẩn hóa cho báo cáo</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

with cc:
    st.markdown(
        """
        <div class="bento-card">
            <div class="bento-icon">📊</div>
            <div class="bento-title">3. AI Analysis Dashboard</div>
            <div style="color: #cdd6f4; font-size: 15px; font-weight: 600; margin-bottom: 8px;">Báo cáo Phân tích AI Security</div>
            <ul style="color: #a6adc8; font-size: 13px; padding-left: 18px; margin-bottom: 0;">
                <li>Lựa chọn file Security Analysis Report JSONL</li>
                <li>Executive Threat Overview Bento Metrics</li>
                <li>Hiển thị bảng lỗ hổng theo nhóm (Grouped View)</li>
                <li>Xem chi tiết Rationale & KB Provenance</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.caption("👈 Sử dụng menu bên trái (Sidebar) để chuyển đổi giữa các trang chức năng.")
