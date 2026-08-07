"""Trang Quét lỗ hổng trực tiếp và Chuẩn hóa Scanner Reports."""

import sys
from pathlib import Path

# Ensure project root is in sys.path for Streamlit execution
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st

from frontend.components.cards import render_section_header
from src.app.normalizer_bridge import (
    execute_normalization,
    list_normalized_files,
    load_unified_findings,
    save_uploaded_report,
)
from src.app.scan_runner import get_supported_scanners, run_scanner

st.set_page_config(page_title="Scan & Normalize - Sentinel", page_icon="🛡️", layout="wide")

st.title("🛡️ Quét Lỗ hổng & Chuẩn hóa Kết quả (Scan & Normalize)")
st.caption("Kích hoạt trực tiếp bài quét SAST/DAST, tải lên tập tin scanner report hoặc chuẩn hóa sang Unified Findings JSONL.")

tab1, tab2, tab3 = st.tabs(["🚀 Quét Trực tiếp (Direct Scan)", "📁 Tải lên / Chọn Raw Report", "⚡ Normalize & View Findings"])

# TAB 1: DIRECT SCAN
with tab1:
    render_section_header("Kích hoạt Bài quét Bảo mật Trực tiếp", "Chạy trực tiếp các công cụ SAST và DAST từ giao diện Web")
    
    col_scanner, col_action = st.columns([3, 1])
    with col_scanner:
        scanners = get_supported_scanners()
        scanner_names = {
            "semgrep": "Semgrep SAST (Quét mã nguồn nhanh)",
            "codeql": "CodeQL SAST (Phân tích Dataflow chuyên sâu)",
            "zap_baseline": "OWASP ZAP Baseline DAST (Passive Scan)",
            "zap_fullscan": "OWASP ZAP Full Scan DAST (Active Crawl & Attack)",
            "sqlmap": "sqlmap DAST (Kiểm thử SQL Injection)",
        }
        selected_tool = st.selectbox(
            "Chọn Scanner muốn thực thi:",
            options=scanners,
            format_func=lambda x: scanner_names.get(x, x),
        )
    
    with col_action:
        st.write(" ")
        st.write(" ")
        start_button = st.button("▶️ Khởi động Scan", type="primary", use_container_width=True)

    if start_button:
        with st.spinner(f"Đang thực thi bài quét {selected_tool}... (Có thể mất từ vài giây đến vài phút)"):
            success, log_output = run_scanner(selected_tool)
            if success:
                st.success(f"Quét thành công bằng {selected_tool}!")
            else:
                st.error(f"Quét thất bại hoặc xuất hiện cảnh báo cho {selected_tool}.")
            
            with st.expander("📄 Xem Terminal Execution Log", expanded=True):
                st.code(log_output, language="bash")

# TAB 2: UPLOAD & SELECT REPORTS
with tab2:
    render_section_header("Quản lý Tập tin Scanner Reports", "Tải lên file log mới hoặc kiểm tra các tập tin hiện có trong reports/raw/")
    
    col_up, col_list = st.columns(2)
    
    with col_up:
        st.markdown("#### Tải lên File Raw Report mới")
        uploaded_file = st.file_uploader(
            "Kéo thả hoặc chọn file raw report (.json, .sarif):",
            type=["json", "sarif"],
        )
        if uploaded_file is not None:
            file_bytes = uploaded_file.read()
            saved_path = save_uploaded_report(uploaded_file.name, file_bytes)
            st.success(f"Đã lưu tập tin thành công tại: `{saved_path}`")

    with col_list:
        st.markdown("#### Các Raw Reports hiện có trong `reports/raw/`")
        raw_dir = Path("reports/raw")
        if raw_dir.exists():
            files = list(raw_dir.glob("*"))
            if files:
                for f in files:
                    st.text(f"📄 {f.name} ({f.stat().st_size} bytes)")
            else:
                st.info("Chưa có file raw report nào trong reports/raw/")
        else:
            st.info("Thư mục reports/raw/ chưa tồn tại.")

# TAB 3: NORMALIZE & VIEW FINDINGS
with tab3:
    render_section_header("Chuẩn hóa Findings sang Unified Format", "Chuyển đổi raw scanner reports sang JSONL tuân thủ unified_findings.schema.json")

    if st.button("⚡ Normalize Tất cả Raw Reports", type="primary"):
        with st.spinner("Đang thực hiện chuẩn hóa..."):
            success, summary = execute_normalization()
            if success:
                st.success("Chuẩn hóa hoàn tất thành công!")
            else:
                st.warning("Chuẩn hóa hoàn tất với cảnh báo hoặc lỗi một phần.")
            st.json(summary)

    st.divider()
    st.markdown("### 📋 Danh sách Unified Findings đã Chuẩn hóa")
    
    normalized_files = list_normalized_files()
    if not normalized_files:
        st.info("Chưa có file Unified Findings nào trong `reports/normalized/`. Vui lòng chạy Normalize ở trên.")
    else:
        selected_file = st.selectbox("Chọn tập tin Normalized Findings:", options=normalized_files)
        if selected_file:
            try:
                findings = load_unified_findings(selected_file)
                st.markdown(f"**Tổng số findings:** `{len(findings)}` phát hiện")
                
                # Filters
                col_f1, col_f2 = st.columns(2)
                with col_f1:
                    tools = list({f.get("tool", "unknown") for f in findings})
                    filter_tool = st.multiselect("Lọc theo Scanner Tool:", options=tools, default=tools)
                with col_f2:
                    severities = list({f.get("severity", "unknown") for f in findings})
                    filter_sev = st.multiselect("Lọc theo Severity:", options=severities, default=severities)

                filtered = [
                    f for f in findings
                    if f.get("tool") in filter_tool and f.get("severity") in filter_sev
                ]

                # Display table
                table_data = []
                for item in filtered:
                    cwe_list = ", ".join(item.get("cwe_ids", [])) or "None"
                    loc = item.get("location", {})
                    loc_str = loc.get("path") or loc.get("url") or "N/A"
                    if loc.get("start_line"):
                        loc_str += f":L{loc.get('start_line')}"
                    
                    table_data.append({
                        "Fingerprint": item.get("fingerprint", "")[:20] + "...",
                        "Tool": item.get("tool", "").upper(),
                        "Scan Type": item.get("scan_type", ""),
                        "Severity": item.get("severity", "").upper(),
                        "Title": item.get("title", ""),
                        "Location": loc_str,
                        "CWE IDs": cwe_list,
                    })

                st.dataframe(table_data, use_container_width=True)

            except Exception as exc:  # noqa: BLE001
                st.error(f"Lỗi khi tải tập tin findings: {exc}")
