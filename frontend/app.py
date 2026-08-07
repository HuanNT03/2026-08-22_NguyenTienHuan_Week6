"""Project Sentinel - DevSecOps & Security AI Analysis Dashboard Entrypoint."""

import os
import urllib.request

import streamlit as st

from frontend.components.cards import render_metric_card

st.set_page_config(
    page_title="Project Sentinel - Security Operations Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ Project Sentinel — DevSecOps Dashboard")
st.caption("Nền tảng kiểm thử và phân tích an toàn thông tin tích hợp OWASP Juice Shop, SAST/DAST Normalizer & AI Security Agent")

st.divider()

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

col1, col2, col3, col4 = st.columns(4)

with col1:
    status_str = "🟢 Online" if is_target_online else "🔴 Offline"
    render_metric_card("Target App (Juice Shop)", status_str, f"Port: {target_port}", key="target_status")

with col2:
    render_metric_card("Knowledge Base", "442+ Docs", "SQLite FTS5 Search Engine", key="kb_count")

with col3:
    render_metric_card("Normalizer Pipeline", "Unified Findings", "Semgrep, CodeQL, ZAP", key="normalizer_status")

with col4:
    render_metric_card("AI Security Agent", "Week 3 Active", "Redaction + KB Provenance", key="agent_status")

st.markdown("### 📌 Hướng dẫn Sử dụng Giao diện Web")

col_a, col_b, col_c = st.columns(3)

with col_a:
    st.info("""
    #### 1. Quét & Chuẩn hóa (Scan & Normalize)
    - Kích hoạt trực tiếp bài quét **Semgrep**, **CodeQL**, **ZAP**, **sqlmap**.
    - Hoặc upload / chọn file raw report sẵn có.
    - Chạy chuẩn hóa kết quả ra **Unified Findings JSONL**.
    """)

with col_b:
    st.success("""
    #### 2. Tra cứu Tri thức (Knowledge Base)
    - Tìm kiếm từ khóa FTS5 trên tập tài liệu **CWE**, **OWASP Top 10**.
    - Tra cứu hướng dẫn khắc phục (Remediation guidelines) và ví dụ lỗ hổng.
    """)

with col_c:
    st.warning("""
    #### 3. Báo cáo Phân tích AI (AI Security Analysis)
    - Kích hoạt **Security Analysis Agent** đọc file Unified Findings.
    - Xem Dashboard 5 thẻ: Tổng quan Rủi ro, Nhóm Lỗ hổng, Nguyên nhân, Vá lỗi & Trích dẫn KB.
    """)

st.divider()
st.markdown("👈 **Chọn trang chức năng ở thanh menu bên trái (Sidebar) để bắt đầu!**")
