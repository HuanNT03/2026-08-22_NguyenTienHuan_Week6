"""Trang Quét lỗ hổng trực tiếp và Chuẩn hóa Scanner Reports (Bento Box Enhanced)."""

from pathlib import Path
import sys

# Ensure project root is in sys.path for Streamlit execution
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st

from frontend.components.bento import inject_bento_css, render_bento_card, render_bento_header
from frontend.components.cards import render_badge
from src.app.normalizer_bridge import (
    execute_normalization,
    list_normalized_files,
    list_raw_report_files,
    load_unified_findings,
    save_uploaded_report,
)
from src.app.scan_runner import (
    check_target_health,
    run_scanner,
    run_scanner_stream,
    run_target_command,
    run_target_command_stream,
)

st.set_page_config(page_title="Scan & Normalize - Sentinel", page_icon="🛡️", layout="wide")

# Inject Bento CSS
inject_bento_css()

st.title("🛡️ Quét Lỗ hổng & Chuẩn hóa Kết quả")
st.caption("Kích hoạt trực tiếp các công cụ SAST/DAST/Full Scan Admin, quản lý vòng đời Target App và chuẩn hóa sang Unified Findings JSONL.")

tab1, tab2, tab3 = st.tabs([
    "🚀 Quét Trực tiếp (Direct Scan)",
    "📁 Quản lý File Raw Reports (Checkbox)",
    "⚡ Normalize & View Findings",
])

# ==========================================
# TAB 1: DIRECT SCAN & TARGET CONTROL (BENTO CARDS)
# ==========================================
with tab1:
    render_bento_header("Quản lý Vòng đời Target App (OWASP Juice Shop)", "Khởi động, dừng và kiểm tra kết nối Target App trước khi thực thi DAST", icon="🎯")

    is_alive, http_code, target_url = check_target_health()
    juice_port = os.getenv("JUICE_SHOP_PORT", "3000")
    host_browser_url = f"http://localhost:{juice_port}/"

    # Equal 3-column Bento Grid for Target App Lifecycle
    col_tg1, col_tg2, col_tg3 = st.columns(3)

    with col_tg1:
        if is_alive:
            status_text = f"🟢 HTTP {http_code} Online"
            badge_var = "success"
            desc_text = f"Container đang chạy & phản hồi tại {target_url}\n(Truy cập từ Host: {host_browser_url})"
            link_target = host_browser_url
        else:
            status_text = "🔴 Offline / Stopped"
            badge_var = "critical"
            desc_text = f"Không thể kết nối HTTP tới {target_url}"
            link_target = None

        render_bento_card(
            title="Target Health Status",
            value=status_text,
            description=desc_text,
            icon="🌐",
            badge_text="Target Container",
            badge_variant=badge_var,
            link_url=link_target,
            link_label="🌐 Mở Web Target App ↗",
        )
        if st.button("🔄 Refresh Health Connection", use_container_width=True, key="btn_refresh_health"):
            st.rerun()

    with col_tg2:
        st.markdown(
            """
            <div style="color: #a6adc8; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px;">
                ⚡ Lifecycle Control Center
            </div>
            """,
            unsafe_allow_html=True,
        )
        btn_start_target = st.button("🚀 Start Target (`make target-up & wait`)", type="primary", use_container_width=True)
        btn_stop_target = st.button("🛑 Stop Target (`make target-down`)", use_container_width=True)
        btn_status_target = st.button("📊 Docker Status (`make target-status`)", use_container_width=True)

    with col_tg3:
        render_bento_card(
            title="Pinned Target Specs",
            value="Juice Shop v20.1.1",
            description="Target lock: target-app/TARGET.lock\nHost Port: 3000 | Container: juice-shop",
            icon="📦",
            badge_text="Target Pinned",
            badge_variant="info",
        )

    # Unified Terminal Execution Output Log for Lifecycle Actions
    target_action_log = None
    log_title = ""

    if btn_start_target:
        term_placeholder = st.empty()
        success = False
        with st.spinner("Đang khởi động Target App và kiểm tra HTTP readiness..."):
            for is_done, full_log, line in run_target_command_stream("up"):
                target_action_log = full_log
                lines = [l for l in full_log.splitlines() if l.strip()]
                display_lines = lines[-15:] if len(lines) > 15 else lines
                term_placeholder.code("\n".join(display_lines) or "$ make target-up", language="bash")
                if is_done:
                    success = not full_log.startswith("Exit code")

            term_placeholder.empty()  # Clear temporary streaming terminal box after completion
            log_title = "🚀 Log Khởi động Target App (`make target-up & wait`)"
            if success:
                st.success("Target App đã khởi động thành công và sẵn sàng nhận kết nối DAST!")
            else:
                st.error("Khởi động Target App thất bại. Vui lòng kiểm tra log bên dưới.")

    if btn_stop_target:
        term_placeholder = st.empty()
        success = False
        with st.spinner("Đang dừng Target App..."):
            for is_done, full_log, line in run_target_command_stream("down"):
                target_action_log = full_log
                lines = [l for l in full_log.splitlines() if l.strip()]
                display_lines = lines[-15:] if len(lines) > 15 else lines
                term_placeholder.code("\n".join(display_lines) or "$ make target-down", language="bash")
                if is_done:
                    success = not full_log.startswith("Exit code")

            term_placeholder.empty()  # Clear temporary streaming terminal box after completion
            log_title = "🛑 Log Đóng Target App (`make target-down`)"
            if success:
                st.success("Target App đã được đóng thành công!")
            else:
                st.error("Lỗi khi dừng Target App. Vui lòng kiểm tra log bên dưới.")

    if btn_status_target:
        term_placeholder = st.empty()
        with st.spinner("Đang lấy thông tin Compose Status..."):
            for is_done, full_log, line in run_target_command_stream("status"):
                target_action_log = full_log
                lines = [l for l in full_log.splitlines() if l.strip()]
                display_lines = lines[-15:] if len(lines) > 15 else lines
                term_placeholder.code("\n".join(display_lines) or "$ make target-status", language="bash")

            term_placeholder.empty()  # Clear temporary streaming terminal box after completion
            log_title = "📊 Log Trạng thái Docker Compose (`make target-status`)"

    if target_action_log:
        with st.expander(f"📄 {log_title}", expanded=True):
            st.code(target_action_log, language="bash")

    st.divider()

    render_bento_header("Bento Tool Selection & Direct Scan", "Chọn công cụ quét SAST, DAST hoặc Full Scan Admin", icon="⚡")

    # Smart DAST Scanner Readiness Warning Banner
    if not is_alive:
        st.warning(
            "⚠️ **Target App (OWASP Juice Shop) hiện đang Offline!**\n\n"
            "Các công cụ quét DAST (OWASP ZAP, sqlmap) cần Target App hoạt động để gửi HTTP request kiểm thử. "
            "Vui lòng bấm nút **'🚀 Start Target'** ở phần Quản lý Vòng đời ở trên trước khi khởi động quét DAST."
        )
    else:
        st.success("🟢 **Target App đang Online tại `http://localhost:3000`** — Sẵn sàng nhận kết nối quét DAST!")

    st.markdown("### 1. Chọn Phân nhóm Công cụ Quét:")

    col_sast, col_dast, col_admin = st.columns(3)

    with col_sast:
        render_bento_card(
            title="SAST Tools (Static)",
            value="Semgrep & CodeQL",
            description="Quét mã nguồn & dataflow analysis trực tiếp trên target codebase.",
            icon="🔍",
            badge_text="Static Scan",
            badge_variant="info",
        )

    with col_dast:
        render_bento_card(
            title="DAST Tools (Dynamic)",
            value="ZAP & sqlmap",
            description="Quét động Baseline, Full Scan Crawl, sqlmap injection test.",
            icon="🌐",
            badge_text="Dynamic Scan",
            badge_variant="success" if is_alive else "critical",
        )

    with col_admin:
        render_bento_card(
            title="Admin & Full Pipeline",
            value="DAST Admin & Week 1",
            description="Quét với quyền Admin Auth (Cookie/Token) & chạy toàn bộ scanner.",
            icon="👑",
            badge_text="Full Scan Admin",
            badge_variant="critical",
        )

    st.divider()

    tool_options = {
        "semgrep": "🔍 Semgrep SAST — Quét mã nguồn tĩnh nhanh",
        "codeql": "🔬 CodeQL SAST — Phân tích Dataflow & Taint tracking chuyên sâu",
        "zap_baseline": "🌐 OWASP ZAP Baseline DAST — Passive Scan web app",
        "zap_fullscan": "🕷️ OWASP ZAP Full Scan DAST — Active Crawl & Attack Surface",
        "zap_admin": "🔐 OWASP ZAP Baseline DAST (Authenticated Admin Session)",
        "zap_fullscan_admin": "👑 OWASP ZAP Full Scan DAST (Authenticated Admin Session)",
        "sqlmap": "💉 sqlmap DAST — Automated SQL Injection Detection & Fingerprint",
        "full_scan_admin": "🚀 Full Scan Admin Pipeline — Chạy toàn bộ SAST + DAST Admin Sequence",
    }

    selected_tool = st.selectbox(
        "Chọn Công cụ Quét muốn Khởi động:",
        options=list(tool_options.keys()),
        format_func=lambda x: tool_options.get(x, x),
    )

    col_btn, col_empty = st.columns([2, 3])
    with col_btn:
        start_button = st.button("▶️ Khởi động Bài quét Ngay", type="primary", use_container_width=True)

    if start_button:
        if not is_alive and selected_tool in ("zap_baseline", "zap_fullscan", "zap_admin", "zap_fullscan_admin", "sqlmap", "full_scan_admin"):
            st.error("❌ Không thể chạy bài quét DAST khi Target App đang Offline! Vui lòng bấm '🚀 Start Target' ở trên trước.")
        else:
            scan_term = st.empty()
            success = False
            log_output = ""
            with st.spinner(f"Đang thực thi bài quét {selected_tool}... (Quá trình có thể mất từ 30s tới vài phút)"):
                for is_done, full_log, line in run_scanner_stream(selected_tool):
                    log_output = full_log
                    lines = [l for l in full_log.splitlines() if l.strip()]
                    display_lines = lines[-15:] if len(lines) > 15 else lines
                    scan_term.code("\n".join(display_lines) or f"$ running {selected_tool}...", language="bash")
                    if is_done:
                        success = not full_log.startswith("Exit code")

                scan_term.empty()  # Clear temporary streaming terminal box after completion
                if success:
                    st.success(f"Bài quét {selected_tool} đã thực thi thành công!")
                else:
                    st.error(f"Bài quét {selected_tool} thất bại hoặc có cảnh báo.")

                with st.expander("📄 Xem Output & Terminal Logs chi tiết", expanded=True):
                    st.code(log_output, language="bash")


# ==========================================
# TAB 2: UPLOAD & CHECKBOX FILE SELECTION
# ==========================================
with tab2:
    render_bento_header("Quản lý Scanner Raw Reports", "Tải lên file report mới hoặc tích chọn nhiều file trong reports/raw/", icon="📁")

    col_upload, col_manage = st.columns([1.5, 2.5])

    with col_upload:
        st.markdown("#### Tải lên File Raw Report")
        uploaded_file = st.file_uploader(
            "Kéo thả hoặc bấm chọn file (.json, .sarif):",
            type=["json", "sarif"],
        )
        if uploaded_file is not None:
            file_bytes = uploaded_file.read()
            saved_path = save_uploaded_report(uploaded_file.name, file_bytes)
            st.success(f"Đã lưu thành công: `{saved_path}`")

    with col_manage:
        st.markdown("#### Các Raw Reports hiện có (`reports/raw/`)")
        raw_files = list_raw_report_files()

        if not raw_files:
            st.info("Chưa có file raw report nào trong thư mục `reports/raw/`.")
        else:
            st.markdown("Tích chọn các tập tin bạn muốn đưa vào tiến trình xử lý:")

            col_sel1, col_sel2 = st.columns([1, 1])
            with col_sel1:
                if st.button("☑️ Chọn tất cả (Select All)"):
                    for f in raw_files:
                        st.session_state[f"chk_raw_{f['name']}"] = True
            with col_sel2:
                if st.button("☐ Bỏ chọn tất cả"):
                    for f in raw_files:
                        st.session_state[f"chk_raw_{f['name']}"] = False

            selected_raw_paths = []
            for f in raw_files:
                chk_key = f"chk_raw_{f['name']}"
                default_val = st.session_state.get(chk_key, True)
                is_selected = st.checkbox(
                    f"📄 `{f['name']}` ({f['size']} bytes)",
                    value=default_val,
                    key=chk_key,
                )
                if is_selected:
                    selected_raw_paths.append(f["path"])

            st.caption(f"Đã chọn **{len(selected_raw_paths)} / {len(raw_files)}** tập tin raw report.")


# ==========================================
# HELPER FUNCTIONS FOR FINDINGS TABLE
# ==========================================
def _get_tool_name(item: dict) -> str:
    tool_val = item.get("tool")
    if isinstance(tool_val, dict):
        return str(tool_val.get("name") or "unknown")
    return str(tool_val or "unknown")


def _get_scan_type(item: dict) -> str:
    tool_val = item.get("tool")
    if isinstance(tool_val, dict):
        return str(tool_val.get("scan_type") or "unknown")
    return str(item.get("scan_type") or "unknown")


def _get_location_str(item: dict) -> str:
    loc = item.get("location", {})
    if not isinstance(loc, dict):
        return "N/A"
    if loc.get("kind") == "code" or "path" in loc:
        path = loc.get("path", "N/A")
        start_line = loc.get("start_line")
        return f"{path}:L{start_line}" if start_line else str(path)
    elif loc.get("kind") == "http" or "uri" in loc or "endpoint" in loc:
        method = loc.get("method") or "GET"
        endpoint = loc.get("endpoint") or loc.get("uri") or "N/A"
        return f"{method} {endpoint}"
    return "N/A"


# ==========================================
# TAB 3: NORMALIZE & VIEW FINDINGS
# ==========================================
with tab3:
    render_bento_header("Chuẩn hóa Findings & Xem Kết quả", "Chuyển đổi các scanner report sang Unified Findings JSONL v2", icon="⚡")

    if st.button("⚡ Normalize Tất cả Raw Reports", type="primary"):
        with st.spinner("Đang thực hiện chuẩn hóa dữ liệu..."):
            success, summary = execute_normalization()
            if success:
                st.success("Chuẩn hóa hoàn tất 100%!")
            else:
                st.warning("Chuẩn hóa hoàn tất với một số cảnh báo.")
            st.json(summary)

    st.divider()
    st.markdown("### 📋 Danh sách Unified Findings đã Chuẩn hóa")

    normalized_files = list_normalized_files()
    if not normalized_files:
        st.info("Chưa có file Unified Findings nào trong `reports/normalized/`. Vui lòng chạy Normalize ở trên.")
    else:
        selected_file = st.selectbox("Chọn tập tin Normalized Findings để kiểm tra:", options=normalized_files)
        if selected_file:
            try:
                findings = load_unified_findings(selected_file)
                st.markdown(f"**Tổng số findings:** `{len(findings)}` phát hiện trong tập tin `{Path(selected_file).name}`")

                # Filters
                col_f1, col_f2 = st.columns(2)
                with col_f1:
                    tools = list({_get_tool_name(f) for f in findings})
                    filter_tool = st.multiselect("Lọc theo Scanner Tool:", options=tools, default=tools)
                with col_f2:
                    severities = list({str(f.get("severity", "unknown")) for f in findings})
                    filter_sev = st.multiselect("Lọc theo Severity:", options=severities, default=severities)

                filtered = [
                    f for f in findings
                    if _get_tool_name(f) in filter_tool and str(f.get("severity", "unknown")) in filter_sev
                ]

                # Display table
                table_data = []
                for item in filtered:
                    cwe_list = ", ".join(item.get("cwe_ids", [])) or "None"
                    table_data.append({
                        "Fingerprint": str(item.get("fingerprint", ""))[:20] + "...",
                        "Group Key": str(item.get("group_key", ""))[:20] + "...",
                        "Tool": _get_tool_name(item).upper(),
                        "Scan Type": _get_scan_type(item),
                        "Severity": str(item.get("severity", "unknown")).upper(),
                        "Title": str(item.get("title") or "N/A"),
                        "Location": _get_location_str(item),
                        "CWE IDs": cwe_list,
                    })

                st.dataframe(table_data, use_container_width=True)

            except Exception as exc:  # noqa: BLE001
                st.error(f"Lỗi khi tải tập tin findings: {exc}")
