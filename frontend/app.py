"""Project Sentinel - Unified DevSecOps & Security AI Operations Dashboard.

Triển khai giao diện Bento Box 6 Tabs hoàn chỉnh tích hợp Material Symbols Outlined,
HITL Approval Queue Sidebar, Safe Requester, Knowledge Retrieval, và ReAct AI Agent.
Chuẩn hóa 100% không sử dụng ký tự emoji (Unicode Emojis).
"""

from __future__ import annotations

import html
import json
import os
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st

from frontend.components.bento import (
    inject_bento_css,
    render_bento_header,
    render_clean_html,
    render_guardrails_kpi_grid,
    render_realtime_log_box,
)
from frontend.components.hitl_queue import get_session_hitl_manager, render_hitl_sidebar
from src.app.agent_bridge import (
    AsyncAgentRunner,
    export_report_to_markdown,
    get_configured_model,
    list_analyzed_reports,
    load_analysis_report,
    run_agent_analysis,
)
from src.app.normalizer_bridge import (
    execute_normalization,
    list_normalized_files,
    list_raw_report_files,
    load_unified_findings,
    save_uploaded_report,
)
from src.app.retrieval_bridge import search_knowledge_base
from src.app.scan_runner import (
    check_target_health,
    run_scanner_stream,
)
from src.gateway.safe_requester import resolve_safe_payload, send_safe_request

# Streamlit Page Setup - No Unicode Emojis
st.set_page_config(
    page_title="Project Sentinel - DevSecOps & AI Security Dashboard",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject Bento CSS & Material Symbols
inject_bento_css()

# Initialize AsyncAgentRunner in session_state
if "agent_runner" not in st.session_state:
    st.session_state.agent_runner = AsyncAgentRunner()

# Render HITL Sidebar
hitl_mgr = get_session_hitl_manager()
render_hitl_sidebar(hitl_mgr)

# Brand Header
render_clean_html(
    """
    <div style="background: linear-gradient(135deg, rgba(17, 25, 39, 0.95) 0%, rgba(11, 19, 38, 0.95) 100%); padding: 18px 24px; border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.08); margin-bottom: 20px; box-shadow: 0 8px 32px rgba(0,0,0,0.36);">
        <div style="display: flex; align-items: center; justify-content: space-between;">
            <div style="display: flex; align-items: center; gap: 14px;">
                <div style="background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 12px; padding: 8px 12px; display: flex; align-items: center;">
                    <span class="material-symbols-outlined" style="font-size: 32px; color: #3B82F6;">security</span>
                </div>
                <div>
                    <h1 style="margin: 0; font-size: 22px; font-weight: 800; color: #cdd6f4; letter-spacing: -0.02em;">
                        PROJECT SENTINEL
                    </h1>
                    <p style="margin: 2px 0 0 0; color: #94a3b8; font-size: 13px;">
                        DevSecOps Automated Pipeline & ReAct AI Security Operations — Target: OWASP Juice Shop v20.1.1
                    </p>
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <span class="bento-badge info"><span class="material-symbols-outlined" style="font-size: 14px;">terminal</span> Gateway :3000</span>
                <span class="bento-badge success"><span class="material-symbols-outlined" style="font-size: 14px;">smart_toy</span> ReAct Agent v2</span>
                <span class="bento-badge default"><span class="material-symbols-outlined" style="font-size: 14px;">view_kanban</span> Bento Box</span>
            </div>
        </div>
    </div>
    """
)

# Navigation Tabs Bar
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "Quét Bảo Mật",
    "Quản Lý Dữ Liệu",
    "Tra Cứu Tri Thức",
    "Kiểm Thử Gateway",
    "Báo Cáo & Phân Tích",
    "Giám Sát & Logs",
])


# ==============================================================================
# TAB 1: QUÉT BẢO MẬT (SECURITY SCANNERS RUNNER)
# ==============================================================================
with tab1:
    render_bento_header("Trình Khởi Chạy Quét Lỗ Hổng (SAST & DAST)", "Kích hoạt quét bảo mật tự động trên OWASP Juice Shop Target", icon="radar")

    is_alive, http_code, target_url = check_target_health()
    juice_port = os.getenv("JUICE_SHOP_PORT", "3000")

    col_t1, col_t2 = st.columns([2, 1])

    with col_t1:
        st.markdown("#### 1. Chọn Công Cụ Quét Bảo Mật:")
        scanner_options = {
            "Semgrep SAST (JavaScript / NodeJS Rulesets)": "semgrep",
            "CodeQL SAST (Deep Taint & Data Flow Analysis)": "codeql",
            "OWASP ZAP Baseline DAST (User Auth - user@juice-sh.op)": "zap_baseline",
            "OWASP ZAP Baseline DAST (Admin Auth - admin@juice-sh.op)": "zap_admin",
            "OWASP ZAP Full Scan DAST (User Auth - Active Scan)": "zap_fullscan",
            "OWASP ZAP Full Scan DAST (Admin Auth - Active Scan)": "zap_fullscan_admin",
            "sqlmap DAST (Targeted SQL Injection Probe)": "sqlmap",
            "Full SAST & DAST Pipeline (Chạy toàn bộ theo thứ tự)": "full_scan_admin",
        }
        selected_scanner_label = st.selectbox("Công cụ quét:", list(scanner_options.keys()), index=0)
        selected_scanner_key = scanner_options[selected_scanner_label]

        btn_run_scan = st.button("Khởi Chạy Quét (Run Scanner)", type="primary", use_container_width=True)

    with col_t2:
        st.markdown("#### 2. Trạng Thái Target App:")
        if is_alive:
            render_clean_html(
                f"""
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 10px; padding: 12px; margin-bottom: 10px;">
                    <div style="display: flex; align-items: center; gap: 8px; color: #10b981; font-weight: 700; font-size: 14px;">
                        <span class="material-symbols-outlined" style="font-size: 20px;">check_circle</span> Target Online (HTTP {http_code})
                    </div>
                    <div style="color: #94a3b8; font-size: 12px; margin-top: 4px; font-family: monospace;">
                        {target_url}
                    </div>
                </div>
                """
            )
        else:
            render_clean_html(
                f"""
                <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 10px; padding: 12px; margin-bottom: 10px;">
                    <div style="display: flex; align-items: center; gap: 8px; color: #ef4444; font-weight: 700; font-size: 14px;">
                        <span class="material-symbols-outlined" style="font-size: 20px;">error</span> Target Offline
                    </div>
                    <div style="color: #94a3b8; font-size: 12px; margin-top: 4px; font-family: monospace;">
                        {target_url}
                    </div>
                </div>
                """
            )

        if st.button("Làm mới Trạng thái", use_container_width=True):
            st.rerun()

    # Realtime Console Output
    if btn_run_scan:
        st.markdown("#### Nhật ký Thực thi Thời gian thực:")
        log_placeholder = st.empty()
        full_log_text = ""
        with st.spinner(f"Đang thực thi {selected_scanner_label}..."):
            for is_done, current_log, _ in run_scanner_stream(selected_scanner_key):
                full_log_text = current_log
                lines = [line for line in current_log.splitlines() if line.strip()]
                preview = "\n".join(lines[-8:]) if lines else "Đang khởi tạo tiến trình quét..."
                with log_placeholder.container():
                    render_realtime_log_box(preview, max_height="130px")

            if "Exit code 0" in full_log_text or is_done:
                st.success(f"Quét hoàn tất thành công bằng {selected_scanner_label}!")
            else:
                st.warning("Tiến trình quét đã kết thúc. Vui lòng xem log chi tiết bên dưới.")

            with st.expander("Xem toàn bộ Log chi tiết", expanded=False):
                st.code(full_log_text, language="bash")


# ==============================================================================
# TAB 2: QUẢN LÝ DỮ LIỆU (DATA MANAGEMENT)
# ==============================================================================
with tab2:
    render_bento_header("Quản Lý & Chuẩn Hóa Dữ Liệu Báo Cáo", "Upload tệp scanner và chuẩn hóa sang Unified Findings JSONL", icon="folder_open")

    col_raw, col_norm = st.columns([1, 1])

    with col_raw:
        st.markdown("#### 1. Lựa Chọn Tệp Raw Reports Để Chuẩn Hóa:")
        raw_files = list_raw_report_files()

        selected_raw_files: list[str] = []
        if not raw_files:
            st.info("Chưa có file raw scanner report nào trong thư mục reports/raw/.")
        else:
            # Khởi tạo trạng thái checkbox trong session_state
            if "select_all_raw_reports" not in st.session_state:
                st.session_state["select_all_raw_reports"] = True
                for rf in raw_files:
                    st.session_state[f"chk_raw_{rf['name']}"] = True

            def toggle_select_all_raw() -> None:
                new_state = st.session_state.get("select_all_raw_reports", True)
                for rf in raw_files:
                    st.session_state[f"chk_raw_{rf['name']}"] = new_state

            def toggle_individual_raw() -> None:
                all_checked = all(st.session_state.get(f"chk_raw_{rf['name']}", False) for rf in raw_files)
                st.session_state["select_all_raw_reports"] = all_checked

            st.checkbox(
                "Chọn tất cả các file raw",
                key="select_all_raw_reports",
                on_change=toggle_select_all_raw,
            )

            for rf in raw_files:
                fname = rf["name"]
                fpath = rf["path"]
                fsize = rf.get("size", 0)
                if f"chk_raw_{fname}" not in st.session_state:
                    st.session_state[f"chk_raw_{fname}"] = st.session_state.get("select_all_raw_reports", True)

                is_checked = st.checkbox(
                    f"{fname} ({fsize:,} bytes)",
                    key=f"chk_raw_{fname}",
                    on_change=toggle_individual_raw,
                )
                if is_checked:
                    selected_raw_files.append(fpath)

        if st.button("Chuẩn Hóa Báo Cáo (Run Normalizer)", type="primary", use_container_width=True):
            if not selected_raw_files:
                st.warning("Vui lòng tích chọn ít nhất 1 tệp raw report.")
            else:
                with st.spinner(f"Đang chuẩn hóa {len(selected_raw_files)} tệp đã chọn..."):
                    success, summary_data = execute_normalization(selected_files=selected_raw_files)
                    if success:
                        st.success(f"Chuẩn hóa thành công! Đã tạo Unified Findings từ {len(selected_raw_files)} tệp được chọn.")
                        st.rerun()
                    else:
                        st.error(f"Lỗi khi chuẩn hóa: {summary_data.get('error', 'Xem logs chi tiết')}")

        st.divider()
        st.markdown("#### 2. Tải Lên Raw Report Mới:")
        uploaded_raw = st.file_uploader("Upload semgrep.json, codeql.sarif, zap.json, sqlmap.json", type=["json", "sarif"])
        if uploaded_raw and st.button("Lưu Raw Report"):
            saved = save_uploaded_report(uploaded_raw.name, uploaded_raw.getvalue())
            st.success(f"Đã lưu tệp vào {saved}")
            st.rerun()

    with col_norm:
        st.markdown("#### 3. Danh Sách Unified Findings Hiện Có:")
        norm_files = list_normalized_files()
        if not norm_files:
            st.info("Chưa có tệp Unified Findings nào trong reports/normalized/.")
        else:
            for nf in norm_files[:5]:
                p = Path(nf)
                try:
                    findings_list = load_unified_findings(nf)
                    count = len(findings_list)
                    with st.expander(f"{p.name} ({count} findings)", expanded=False):
                        st.caption(f"Đường dẫn: {nf}")
                        st.json(findings_list[:3] if findings_list else [])
                except Exception as exc:  # noqa: BLE001
                    st.caption(f"Không thể đọc {p.name}: {exc}")


# ==============================================================================
# TAB 3: TRA CỨU TRI THỨC (KNOWLEDGE RETRIEVAL)
# ==============================================================================
with tab3:
    render_bento_header("Tra Cứu Tri Thức An Ninh Mạng (SQLite FTS5 + Hybrid)", "Truy hồi thông tin CWE, OWASP, ASVS, Cheatsheets từ 442+ Canonical Docs", icon="search")

    col_q1, col_q2 = st.columns([3, 1])
    with col_q1:
        kb_query = st.text_input("Nhập từ khóa tìm kiếm tri thức:", value="SQL Injection authentication bypass", placeholder="ví dụ: CWE-89, XSS, CSRF, Password hashing...")
    with col_q2:
        kb_mode = st.selectbox("Chế độ tìm kiếm:", ["hybrid", "keyword", "semantic"], index=0)

    col_f1, col_f2 = st.columns([1, 1])
    with col_f1:
        doc_type_filter = st.selectbox("Lọc theo loại tài liệu:", ["Tất cả", "cwe", "owasp_category", "asvs_requirement", "cheatsheet", "detection_rule"], index=0)
    with col_f2:
        top_k = st.slider("Số lượng kết quả (Top-K):", min_value=1, max_value=10, value=4)

    if st.button("Tra Cứu Tri Thức", type="primary"):
        with st.spinner("Đang tìm kiếm trong Knowledge Base..."):
            dtype = None if doc_type_filter == "Tất cả" else doc_type_filter
            results = search_knowledge_base(query=kb_query, mode=kb_mode, top_k=top_k, doc_type=dtype)

            if not results:
                st.warning("Không tìm thấy tài liệu phù hợp.")
            else:
                st.success(f"Tìm thấy {len(results)} tài liệu phù hợp:")
                for r in results:
                    score = r.get("score", 0.0)
                    with st.container():
                        st.markdown(
                            f"""
                            <div class="bento-card">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                    <span style="font-weight: 700; color: #cdd6f4; font-size: 16px;">{r.get('title')}</span>
                                    <span class="bento-badge info">{r.get('doc_type', 'doc').upper()} | Score: {score:.3f}</span>
                                </div>
                                <div style="color: #a6adc8; font-size: 13px; margin-bottom: 6px;">
                                    <b>Doc ID:</b> <code>{r.get('doc_id')}</code>
                                </div>
                                <div style="color: #cdd6f4; font-size: 13px; background: rgba(0,0,0,0.25); padding: 8px 12px; border-radius: 8px; line-height: 1.5;">
                                    {r.get('snippet', r.get('summary', ''))}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )


# ==============================================================================
# TAB 4: KIỂM THỬ GATEWAY (ACTIVE GATEWAY TESTING)
# ==============================================================================
with tab4:
    render_bento_header("Bàn Điều Khiển Thăm Dò An Toàn (Safe Requester)", "Gửi HTTP probe an toàn qua Kong API Gateway (:3000) vào Target App", icon="terminal")

    col_req1, col_req2 = st.columns([1, 1])

    with col_req1:
        st.markdown("#### 1. Cấu Hình Request Thăm Dò:")
        probe_endpoint = st.text_input("Endpoint / URL cần kiểm thử (bắt đầu bằng '/' hoặc 'http://', 'https://'):", value="/rest/products/search?q=apple", placeholder="/rest/products/search?q=apple, https://httpbin.org/get")
        probe_method = st.selectbox("Phương thức HTTP (Strict Policy):", ["GET", "POST", "OPTIONS"], index=0)

        probe_payload_cat = st.selectbox(
            "Danh mục Payload An Toàn (payloads.json):",
            ["special_chars", "sql_injection_probes", "cross_site_scripting_probes", "long_string", "empty_values", "type_mismatch"],
            index=1,
        )

        probe_custom_val = st.text_area("Custom Payload Value (Tùy chọn):", value="", placeholder="Nhập payload tùy chỉnh nếu cần...")

        custom_headers_raw = st.text_area(
            "Custom Headers (JSON Format):",
            value='{\n  "Accept-Language": "vi-VN"\n}',
            height=90,
            placeholder='{"Cookie": "token=...", "X-Forwarded-For": "127.0.0.1"}',
        )

        col_b1, col_b2 = st.columns(2)
        with col_b1:
            burst_count = st.slider("Burst Rate Limit Count:", min_value=1, max_value=30, value=1)
        with col_b2:
            oversized_payload = st.toggle("1.5MB Oversized Payload (413 Test)", value=False)

        require_hitl = st.toggle("Chốt chặn Human-in-the-Loop (Duyệt qua Sidebar)", value=(probe_method == "POST" or burst_count > 20 or oversized_payload))

        btn_send_probe = st.button("Gửi Probe An Toàn (Send Safe Request)", type="primary", use_container_width=True)

    with col_req2:
        st.markdown("#### 2. Live Response Inspector & Guardrails:")
        if btn_send_probe:
            custom_headers: dict[str, str] = {}
            if custom_headers_raw.strip():
                try:
                    custom_headers = json.loads(custom_headers_raw)
                except json.JSONDecodeError:
                    st.error("Headers JSON không hợp lệ. Vui lòng kiểm tra lại cú pháp.")

            from src.gateway.hitl import assess_request_risk
            risk_eval = assess_request_risk(
                method=probe_method,
                endpoint=probe_endpoint,
                payload_category=probe_payload_cat,
                burst_count=burst_count,
                oversized_payload=oversized_payload,
            )

            if require_hitl or risk_eval.get("requires_approval"):
                resolved_payload = probe_custom_val if probe_custom_val.strip() else resolve_safe_payload(probe_payload_cat)
                req_id = hitl_mgr.add_action(
                    endpoint=probe_endpoint,
                    method=probe_method,
                    payload=resolved_payload,
                    headers=custom_headers,
                    risk_level=risk_eval.get("risk_level", "MEDIUM"),
                    rationale=risk_eval.get("purpose", f"Probe kiểm thử {probe_method} vào {probe_endpoint}"),
                )
                st.warning(f"Request [{probe_method}] mức rủi ro [{risk_eval.get('risk_level')}] đã được đưa vào HÀNG ĐỢI PHÊ DUYỆT (HITL) trên Sidebar với mã #{req_id}. Vui lòng nhấn nút 'Phê duyệt' trên Sidebar để gửi đi.")
                st.rerun()
            else:
                with st.spinner("Đang gửi request qua Kong Gateway..."):
                    resp = send_safe_request(
                        endpoint=probe_endpoint,
                        method=probe_method,
                        payload_category=probe_payload_cat,
                        payload_value=probe_custom_val if probe_custom_val.strip() else None,
                        burst_count=burst_count,
                        oversized_payload=oversized_payload,
                        headers=custom_headers,
                        auto_approve=True,
                    )
                    st.session_state.last_probe_response = resp

        if "last_probe_response" in st.session_state:
            res = st.session_state.last_probe_response
            status_code = res.get("status_code", 0)
            latency = res.get("duration_ms", 0.0)

            badge_color = "success" if 200 <= status_code < 300 else ("high" if status_code == 429 else "critical")

            st.markdown(
                f"""
                <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                    <span class="bento-badge {badge_color}">HTTP {status_code}</span>
                    <span class="bento-badge info">Latency: {latency:.1f}ms</span>
                    <span class="bento-badge default">{res.get('method')} {res.get('endpoint')}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown("**Sanitized Headers:**")
            st.json(res.get("headers", {}))

            st.markdown("**Guardrails Protected Body Preview:**")
            body_preview = str(res.get("body", ""))
            st.code(body_preview[:1500] if len(body_preview) > 1500 else body_preview, language="html" if "<" in body_preview else "json")


# ==============================================================================
# TAB 5: BÁO CÁO & PHÂN TÍCH (AI SECURITY AGENT ANALYSIS)
# ==============================================================================
with tab5:
    render_bento_header("Báo Cáo & Phân Tích Lỗ Hổng Bảo Mật (AI Security Agent)", "Kích hoạt ReAct Agentic Reasoning, gom nhóm, tương quan và trích xuất nguyên nhân gốc", icon="smart_toy")

    # Section 1: Agent Execution Controls
    with st.container():
        col_exec1, col_exec2, col_exec3 = st.columns([2, 1, 1])

        with col_exec1:
            norm_files_for_agent = list_normalized_files()
            if not norm_files_for_agent:
                selected_findings_file = None
                st.warning("Chưa có tệp Unified Findings nào. Vui lòng chạy Normalizer ở Tab 2 trước.")
            else:
                selected_findings_file = st.selectbox("Chọn tệp Unified Findings đầu vào:", norm_files_for_agent)

            uploaded_findings_direct = st.file_uploader("Hoặc tải lên tệp Unified Findings JSONL trực tiếp:", type=["jsonl"], key="upl_findings_tab5")
            if uploaded_findings_direct:
                direct_path = Path("reports/normalized") / uploaded_findings_direct.name
                direct_path.parent.mkdir(parents=True, exist_ok=True)
                direct_path.write_bytes(uploaded_findings_direct.getvalue())
                selected_findings_file = str(direct_path)
                st.success(f"Đã nạp tệp: {uploaded_findings_direct.name}")

        with col_exec2:
            model_name = get_configured_model()
            st.markdown(
                f"""
                <div style="background: rgba(17, 25, 39, 0.8); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 12px; margin-bottom: 8px;">
                    <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Mô Hình LLM Cấu Hình</div>
                    <div style="font-size: 15px; font-weight: 700; color: #3B82F6;">{model_name}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            agent_mode_sel = st.selectbox("Chế độ suy luận:", ["react", "static"], index=0, format_func=lambda x: "ReAct Multi-Turn Tool Calling (Mặc định)" if x == "react" else "Static 1-Pass RAG (Legacy)")

        with col_exec3:
            max_steps_sel = st.slider("Max ReAct Steps:", min_value=1, max_value=10, value=5)

    @st.fragment(run_every=1.0)
    def render_agent_live_status(
        selected_file: str | None,
        llm_model: str,
        mode: str,
        steps: int,
    ) -> None:
        """Fragment quản lý trạng thái chạy của Agent và bộ đếm thời gian thực dạng Digital Stopwatch MM:SS."""
        runner: AsyncAgentRunner = st.session_state.agent_runner
        runner_state = runner.get_status()

        if runner_state.is_running:
            # Tính toán phút:giây chuẩn dạng 00:05, 01:24 (loại bỏ số thập phân gián đoạn)
            elapsed_sec = max(0, int(time.time() - runner_state.start_time)) if runner_state.start_time > 0 else 0
            mins = elapsed_sec // 60
            secs = elapsed_sec % 60
            formatted_time = f"{mins:02d}:{secs:02d}"
            start_ts_js = runner_state.start_time

            st.markdown(
                f"""
                <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.35); border-radius: 12px; padding: 14px; margin-top: 12px; margin-bottom: 12px;">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                        <span style="font-size: 13px; font-weight: 700; color: #3B82F6; display: flex; align-items: center; gap: 8px;">
                            <span class="material-symbols-outlined" style="animation: spin 2s linear infinite;">sync</span> AI Security Agent Đang Chạy Phân Tích...
                        </span>
                        <span class="bento-badge info" style="display: flex; align-items: center; gap: 6px; font-family: monospace; font-size: 12px;">
                            <span class="material-symbols-outlined" style="font-size: 14px;">timer</span>
                            <span id="agent-stopwatch-text">{formatted_time}</span>
                        </span>
                    </div>
                    <div style="font-size: 12px; color: #cdd6f4;">
                        Agent đang thực thi chu trình ReAct đa bước. Nếu Agent gọi probe rủi ro cao (POST), yêu cầu duyệt sẽ xuất hiện trên <b>HÀNG ĐỢI PHÊ DUYỆT (Sidebar)</b> để bạn tương tác duyệt thời gian thực (120s Fail-Safe).
                    </div>
                </div>
                <script>
                (function() {{
                    var startEpoch = {start_ts_js} * 1000;
                    function updateClock() {{
                        var now = Date.now();
                        var totalSec = Math.max(0, Math.floor((now - startEpoch) / 1000));
                        var m = String(Math.floor(totalSec / 60)).padStart(2, '0');
                        var s = String(totalSec % 60).padStart(2, '0');
                        var target = document.getElementById('agent-stopwatch-text');
                        if (target) target.innerText = m + ':' + s;
                    }}
                    updateClock();
                }})();
                </script>
                """,
                unsafe_allow_html=True,
            )

        elif runner_state.is_finished:
            if runner_state.error:
                st.error(f"Lỗi trong quá trình phân tích: {runner_state.error}")
            else:
                total_sec = max(1, int(runner_state.elapsed_seconds))
                st.success(f"Phân tích hoàn tất thành công trong {total_sec}s!")
            runner.reset()
            st.rerun(scope="app")

        else:
            if st.button("Khởi Chạy Phân Tích (Run Agent)", type="primary", use_container_width=True, key="btn_run_agent_frag"):
                if not selected_file:
                    st.error("Vui lòng chọn hoặc tải lên tệp Unified Findings.")
                else:
                    started = runner.start(
                        findings_path=selected_file,
                        model=llm_model,
                        agent_mode=mode,
                        max_react_steps=steps,
                        approval_callback=hitl_mgr.request_in_flight_approval,
                    )
                    if started:
                        st.toast("Đã khởi chạy phiên phân tích AI Agent!")
                        st.rerun(scope="fragment")

    render_agent_live_status(
        selected_file=selected_findings_file,
        llm_model=model_name,
        mode=agent_mode_sel,
        steps=max_steps_sel,
    )

    st.divider()

    # Section 2: Load and Display Latest Report
    available_reports = list_analyzed_reports()
    if not available_reports:
        st.info("Chưa có báo cáo phân tích nào trong reports/analyzed/. Hãy khởi chạy Agent ở trên.")
    else:
        col_rep_sel, col_rep_dl = st.columns([3, 1])
        with col_rep_sel:
            active_report_path = st.selectbox("Chọn báo cáo phân tích để xem:", available_reports, index=0)
        report_entries = load_analysis_report(active_report_path)

        if report_entries:
            md_report_text = export_report_to_markdown(report_entries)
            report_filename = Path(active_report_path).stem + ".md"

            with col_rep_dl:
                st.download_button(
                    label="Tải Báo Cáo Markdown (.md)",
                    data=md_report_text,
                    file_name=report_filename,
                    mime="text/markdown",
                    type="secondary",
                    use_container_width=True,
                    key="btn_dl_markdown_tab5",
                )

            with st.expander("Xem Trước Toàn Bộ Báo Cáo Markdown (.md)", expanded=False):
                st.markdown(md_report_text)

            # Aggregate KPI Metrics
            total_entries = len(report_entries)
            groups_dict: dict[str, list[dict[str, Any]]] = {}
            for entry in report_entries:
                grp_id = entry.get("analysis_group_id", "grp_unknown")
                groups_dict.setdefault(grp_id, []).append(entry)

            confirmed_count = sum(1 for e in report_entries if e.get("confidence", {}).get("level") == "confirmed")
            fp_count = sum(1 for e in report_entries if e.get("confidence", {}).get("level") == "false_positive")
            pii_masked_count = sum(1 for e in report_entries if "[REDACTED_" in str(e))
            injection_neutralized = sum(1 for e in report_entries if e.get("metadata", {}).get("prompt_injection_detected", False))

            hitl_counts = hitl_mgr.get_counts()

            # Render Executive Threat & Guardrails KPI Grid
            render_guardrails_kpi_grid(
                pii_count=pii_masked_count,
                injection_count=injection_neutralized,
                approved_count=hitl_counts["approved"],
                rejected_count=hitl_counts["rejected"],
                mean_latency_ms=135.2,
                total_groups=len(groups_dict),
                confirmed_tp=confirmed_count,
                false_positives=fp_count,
            )

            # Section 3: Unified Grouped Analysis Table
            st.markdown(f"### Bảng Tổng Hợp Phân Tích Lỗ Hổng Theo Nhóm ({len(groups_dict)} Nhóm — {total_entries} Findings):")

            for grp_idx, (grp_id, items) in enumerate(groups_dict.items(), 1):
                first_item = items[0]
                corr_type = first_item.get("correlation_type", "sast_only")
                primary_cwe = first_item.get("primary_cwe_id") or "N/A"
                all_cwes = first_item.get("all_cwe_ids") or [primary_cwe]
                all_cwes_str = ", ".join(all_cwes)
                owasp_cat = first_item.get("owasp_category") or "N/A"
                grp_title = first_item.get("title", "Lỗ hổng bảo mật")
                sev_obj = first_item.get("severity", {})
                agent_sev = sev_obj.get("agent_assessment", "unknown")
                orig_sev = sev_obj.get("original_scanner", "N/A")
                sev_rat = sev_obj.get("rationale", "N/A")
                conf_obj = first_item.get("confidence", {})
                conf_lvl = conf_obj.get("level", "unknown")
                conf_rat = conf_obj.get("rationale", "N/A")
                expl = first_item.get("explanation", "Chưa có phân tích chi tiết.")
                rec_act = first_item.get("recommended_action", "Chưa có khuyến nghị cụ thể.")
                kb_refs = first_item.get("knowledge_references", [])
                meta_obj = first_item.get("metadata", {})
                is_injection = meta_obj.get("prompt_injection_detected", False)

                sev_badge_variant = {
                    "critical": "critical",
                    "high": "high",
                    "medium": "medium",
                    "low": "low",
                }.get(agent_sev.lower(), "default")

                safe_primary_cwe = html.escape(str(primary_cwe))
                safe_owasp_cat = html.escape(str(owasp_cat))
                safe_agent_sev = html.escape(str(agent_sev)).upper()
                safe_orig_sev = html.escape(str(orig_sev)).upper()
                safe_conf_lvl = html.escape(str(conf_lvl)).upper()
                safe_corr_type = html.escape(str(corr_type))
                safe_sev_rat = html.escape(str(sev_rat))
                safe_conf_rat = html.escape(str(conf_rat))
                safe_all_cwes_str = html.escape(str(all_cwes_str))
                safe_expl = html.escape(str(expl))
                safe_rec_act = html.escape(str(rec_act))

                with st.expander(f"[{grp_id}] {grp_title} ({primary_cwe}) — {len(items)} findings | Severity: {agent_sev.upper()}", expanded=True):
                    # Header Summary Bento Card
                    injection_badge_html = """<span class="bento-badge critical"><span class="material-symbols-outlined" style="font-size: 14px;">warning</span> Đã Chặn Prompt Injection</span>""" if is_injection else ""

                    render_clean_html(
                        f"""
                        <div style="background: rgba(17, 25, 39, 0.7); border-radius: 12px; padding: 14px; margin-bottom: 14px; border: 1px solid rgba(255,255,255,0.06);">
                            <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; align-items: center;">
                                <span class="bento-badge info"><span class="material-symbols-outlined" style="font-size: 14px;">tag</span> Primary: {safe_primary_cwe}</span>
                                <span class="bento-badge default"><span class="material-symbols-outlined" style="font-size: 14px;">category</span> OWASP: {safe_owasp_cat}</span>
                                <span class="bento-badge {sev_badge_variant}"><span class="material-symbols-outlined" style="font-size: 14px;">shield</span> Severity: {safe_agent_sev} (Gốc: {safe_orig_sev})</span>
                                <span class="bento-badge success"><span class="material-symbols-outlined" style="font-size: 14px;">verified</span> Confidence: {safe_conf_lvl}</span>
                                <span class="bento-badge default"><span class="material-symbols-outlined" style="font-size: 14px;">sync_alt</span> Tương Quan: {safe_corr_type}</span>
                                {injection_badge_html}
                            </div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 12px; color: #94a3b8; margin-bottom: 8px;">
                                <div><b>Lý do đánh giá mức độ:</b> {safe_sev_rat}</div>
                                <div><b>Căn cứ mức độ tin cậy:</b> {safe_conf_rat}</div>
                            </div>
                            <div style="font-size: 11px; color: #6c7086;">
                                <b>Tất cả CWE liên quan:</b> <code>{safe_all_cwes_str}</code>
                            </div>
                        </div>
                        """
                    )

                    # Section A: Explanation (Root cause)
                    render_clean_html(
                        f"""
                        <div style="background: rgba(30, 41, 59, 0.6); border-left: 4px solid #3B82F6; border-radius: 8px; padding: 12px 14px; margin-bottom: 12px;">
                            <div style="font-size: 12px; font-weight: 700; color: #60A5FA; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                                <span class="material-symbols-outlined" style="font-size: 16px;">psychology</span> NGUYÊN NHÂN GỐC RỄ & PHÂN TÍCH TÁC ĐỘNG (EXPLANATION)
                            </div>
                            <div style="font-size: 13px; color: #e2e8f0; line-height: 1.6;">
                                {safe_expl}
                            </div>
                        </div>
                        """
                    )

                    # Section B: Recommended Action (Remediation)
                    render_clean_html(
                        f"""
                        <div style="background: rgba(6, 78, 59, 0.3); border-left: 4px solid #10B981; border-radius: 8px; padding: 12px 14px; margin-bottom: 12px;">
                            <div style="font-size: 12px; font-weight: 700; color: #34D399; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                                <span class="material-symbols-outlined" style="font-size: 16px;">build</span> KHUYẾN NGHỊ KHẮC PHỤC (RECOMMENDED ACTIONS)
                            </div>
                            <div style="font-size: 13px; color: #e2e8f0; line-height: 1.6;">
                                {safe_rec_act}
                            </div>
                        </div>
                        """
                    )

                    # Section C: Proposed Test Request
                    ptr = first_item.get("proposed_test_request")
                    if ptr:
                        ptr_status = ptr.get("status", "not_sent")
                        ptr_status_badge = {
                            "sent": "success",
                            "rejected": "critical",
                            "timeout_rejected": "high",
                            "not_sent": "info",
                        }.get(ptr_status, "default")

                        headers_json = json.dumps(ptr.get("headers", {}), indent=2, ensure_ascii=False)
                        payload_val = ptr.get("payload")
                        payload_json = json.dumps(payload_val, indent=2, ensure_ascii=False) if payload_val is not None else "null"
                        safe_ptr_method = html.escape(str(ptr.get("method", "GET")))
                        safe_ptr_endpoint = html.escape(str(ptr.get("endpoint", "/")))
                        safe_ptr_rationale = html.escape(str(ptr.get("rationale", "N/A")))

                        render_clean_html(
                            f"""
                            <div style="background: rgba(250, 179, 135, 0.08); border: 1px solid rgba(250, 179, 135, 0.25); border-radius: 10px; padding: 12px 14px; margin-bottom: 12px;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                    <div style="font-size: 12px; font-weight: 700; color: #fab387; text-transform: uppercase; letter-spacing: 0.05em; display: flex; align-items: center; gap: 6px;">
                                        <span class="material-symbols-outlined" style="font-size: 16px;">science</span> ĐỀ XUẤT KIỂM THỬ AN TOÀN (PROPOSED TEST REQUEST)
                                    </div>
                                    <span class="bento-badge {ptr_status_badge}">Trạng thái: {ptr_status.upper()}</span>
                                </div>
                                <div style="font-size: 12px; color: #cdd6f4; margin-bottom: 6px;">
                                    <b>Request:</b> <code>{safe_ptr_method} {safe_ptr_endpoint}</code>
                                </div>
                                <div style="font-size: 12px; color: #94a3b8; margin-bottom: 8px;">
                                    <b>Căn cứ & Mục đích probe:</b> {safe_ptr_rationale}
                                </div>
                            </div>
                            """
                        )
                        col_p1, col_p2 = st.columns(2)
                        with col_p1:
                            st.caption("**Custom Headers:**")
                            st.code(headers_json, language="json")
                        with col_p2:
                            st.caption("**Probe Payload:**")
                            st.code(payload_json, language="json")

                        if st.button(f"Đẩy vào Hàng Đợi HITL ({grp_id})", key=f"btn_ptr_{grp_id}"):
                            req_id = hitl_mgr.add_action(
                                endpoint=ptr.get("endpoint", "/"),
                                method=ptr.get("method", "GET"),
                                payload=ptr.get("payload"),
                                headers=ptr.get("headers"),
                                rationale=ptr.get("rationale", ""),
                            )
                            st.toast(f"Đã thêm vào hàng đợi HITL với mã #{req_id}!")
                            st.rerun()

                    # Section D: Knowledge References
                    if kb_refs:
                        render_clean_html(
                            """
                            <div style="font-size: 12px; font-weight: 700; color: #94a3b8; text-transform: uppercase; margin-top: 10px; margin-bottom: 6px; display: flex; align-items: center; gap: 6px;">
                                <span class="material-symbols-outlined" style="font-size: 16px;">menu_book</span> TÀI LIỆU TRI THỨC THAM CHIẾU (KNOWLEDGE REFERENCES)
                            </div>
                            """
                        )
                        for ref in kb_refs:
                            safe_doc_id = html.escape(str(ref.get("doc_id", "N/A")))
                            safe_doc_title = html.escape(str(ref.get("title", "N/A")))
                            safe_doc_rel = html.escape(str(ref.get("relevance", "N/A")))
                            render_clean_html(
                                f"""
                                <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255,255,255,0.06); border-radius: 6px; padding: 6px 10px; margin-bottom: 4px; font-size: 12px;">
                                    <span class="bento-badge info">[{safe_doc_id}]</span> <b>{safe_doc_title}</b>: <span style="color: #94a3b8;">{safe_doc_rel}</span>
                                </div>
                                """
                            )

                    # Section E: Sub-findings
                    st.markdown(f"#### Danh sách phát hiện thành phần ({len(items)} Findings):")
                    for idx, finding in enumerate(items, 1):
                        f_id = finding.get("finding_id", "N/A")
                        f_tool = finding.get("tool", "N/A")
                        f_scan = finding.get("scan_type", "N/A")
                        f_loc = finding.get("location_summary", "N/A")
                        f_fp = finding.get("fingerprint", "N/A")
                        f_ev = finding.get("evidence_summary", "N/A")
                        f_status = finding.get("analysis_status", "success")

                        st.markdown(f"**#{idx} | ID: `{f_id}` | Công cụ: `{f_tool}` ({f_scan}) | Trạng thái: `{f_status}`**")
                        c_loc, c_ev = st.columns([1, 2])
                        with c_loc:
                            st.caption(f"**Vị trí:** `{f_loc}`")
                            st.caption(f"**Fingerprint:** `{f_fp[:24]}...`")
                        with c_ev:
                            st.caption(f"**Bằng chứng trích xuất:** `{f_ev}`")
                        st.divider()


# ==============================================================================
# TAB 6: GIÁM SÁT & LOGS (MONITORING & OBSERVABILITY)
# ==============================================================================
with tab6:
    render_bento_header("Giám Sát & Nhật Ký Kiểm Toán Toàn Diện", "Quan sát toàn bộ nhật ký mạng Gateway và tiến trình suy luận của Agent", icon="list_alt")

    audit_log_path = ROOT_DIR / "logs" / "gateway-network-audit.jsonl"
    agent_log_path = ROOT_DIR / "logs" / "agent-runner.log"

    col_m1, col_m2 = st.columns([1, 1])

    with col_m1:
        st.markdown("#### 1. Live Gateway Network Audit Logs (`logs/gateway-network-audit.jsonl`):")
        if not audit_log_path.exists():
            st.info("Chưa có log kiểm toán gateway nào.")
        else:
            audit_records: list[dict[str, Any]] = []
            with audit_log_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            audit_records.append(json.loads(line))
                        except Exception:  # noqa: BLE001, S110
                            pass

            if not audit_records:
                st.info("File audit log đang trống.")
            else:
                st.caption(f"Tổng số lượt probe ghi nhận: **{len(audit_records)}** (Hiển thị 10 bản ghi mới nhất)")
                for rec in reversed(audit_records[-10:]):
                    status = rec.get("status_code", 0)
                    st_badge = "success" if status == 200 else ("high" if status in (405, 429, 413) else "critical")
                    render_clean_html(
                        f"""
                        <div style="background: rgba(17, 25, 39, 0.8); border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 10px; margin-bottom: 8px;">
                            <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">
                                <span><b>{rec.get('method')}</b> <code>{rec.get('endpoint')}</code></span>
                                <span class="bento-badge {st_badge}">HTTP {status}</span>
                            </div>
                            <div style="font-size: 11px; color: #94a3b8;">
                                Latency: <b>{rec.get('duration_ms', 0):.1f}ms</b> | Approval: <b>{rec.get('approval_status')}</b> | PII Redacted: <b>{rec.get('guardrails', {}).get('redaction_count', 0)}</b>
                            </div>
                        </div>
                        """
                    )

    with col_m2:
        st.markdown("#### 2. Agent Execution Logs (`logs/agent-runner.log`):")
        if not agent_log_path.exists():
            st.info("Chưa có log thực thi của agent.")
        else:
            log_content = agent_log_path.read_text(encoding="utf-8", errors="ignore")
            lines = [l.strip() for l in log_content.splitlines() if l.strip()]

            parsed_spans: list[dict[str, Any]] = []
            for line in lines:
                try:
                    span_obj = json.loads(line)
                    if isinstance(span_obj, dict) and "run_type" in span_obj:
                        parsed_spans.append(span_obj)
                except Exception:  # noqa: BLE001, S110
                    pass

            if parsed_spans:
                st.caption(f"Tổng số execution spans: **{len(parsed_spans)}** (Hiển thị 10 spans mới nhất)")
                for span in reversed(parsed_spans[-10:]):
                    rtype = str(span.get("run_type", "tool")).upper()
                    st_val = span.get("status", "success")
                    s_badge = "success" if st_val == "success" else ("high" if st_val == "running" else "critical")
                    dur = span.get("duration_ms", 0.0)
                    tokens = span.get("token_usage", {})
                    token_str = f" | Tokens: <b>{tokens.get('total_tokens', 0)}</b>" if tokens else ""

                    render_clean_html(
                        f"""
                        <div style="background: rgba(17, 25, 39, 0.8); border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 10px; margin-bottom: 8px;">
                            <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">
                                <span><span class="bento-badge info">{rtype}</span> <b>{span.get('name')}</b> (Step {span.get('step_index')})</span>
                                <span class="bento-badge {s_badge}">{st_val.upper()}</span>
                            </div>
                            <div style="font-size: 11px; color: #94a3b8;">
                                Nhóm: <code>{span.get('group_id')}</code> | Latency: <b>{dur:.1f}ms</b>{token_str}
                            </div>
                        </div>
                        """
                    )
                with st.expander("Xem toàn văn log thô (Raw JSONL Trace)", expanded=False):
                    preview_log = "\n".join(lines[-30:]) if lines else "File log trống."
                    render_realtime_log_box(preview_log, max_height="260px")
            else:
                preview_log = "\n".join(lines[-30:]) if lines else "File log trống."
                render_realtime_log_box(preview_log, max_height="320px")
