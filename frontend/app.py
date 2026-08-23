"""Project Sentinel - Unified DevSecOps & Security AI Operations Dashboard.

Triển khai giao diện Bento Box 6 Tabs hoàn chỉnh tích hợp Material Symbols Outlined,
HITL Approval Queue Sidebar, Safe Requester, Knowledge Retrieval, và ReAct AI Agent.
Chuẩn hóa 100% không sử dụng ký tự emoji (Unicode Emojis).
"""

from __future__ import annotations

import json
import os
import sys
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
    render_guardrails_kpi_grid,
    render_realtime_log_box,
)
from frontend.components.hitl_queue import get_session_hitl_manager, render_hitl_sidebar
from src.app.agent_bridge import (
    AsyncAgentRunner,
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
st.markdown(
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
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# 6 Navigation Tabs
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
            st.markdown(
                f"""
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 10px; padding: 12px; margin-bottom: 10px;">
                    <div style="display: flex; align-items: center; gap: 8px; color: #10b981; font-weight: 700; font-size: 14px;">
                        <span class="material-symbols-outlined" style="font-size: 20px;">check_circle</span> Target Online (HTTP {http_code})
                    </div>
                    <div style="color: #94a3b8; font-size: 12px; margin-top: 4px; font-family: monospace;">
                        {target_url}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 10px; padding: 12px; margin-bottom: 10px;">
                    <div style="display: flex; align-items: center; gap: 8px; color: #ef4444; font-weight: 700; font-size: 14px;">
                        <span class="material-symbols-outlined" style="font-size: 20px;">error</span> Target Offline
                    </div>
                    <div style="color: #94a3b8; font-size: 12px; margin-top: 4px; font-family: monospace;">
                        {target_url}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
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
            btn_run_agent = st.button("Khởi Chạy Phân Tích (Run Agent)", type="primary", use_container_width=True)

    runner: AsyncAgentRunner = st.session_state.agent_runner
    runner_state = runner.get_status()

    if runner_state.is_running:
        st.markdown(
            f"""
            <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.35); border-radius: 12px; padding: 14px; margin-top: 12px; margin-bottom: 12px;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                    <span style="font-size: 13px; font-weight: 700; color: #3B82F6; display: flex; align-items: center; gap: 8px;">
                        <span class="material-symbols-outlined">sync</span> AI Security Agent Đang Chạy Phân Tích...
                    </span>
                    <span class="bento-badge info">Thời gian: {runner_state.elapsed_seconds:.1f}s</span>
                </div>
                <div style="font-size: 12px; color: #cdd6f4;">
                    Agent đang thực thi chu trình ReAct đa bước. Nếu Agent gọi probe rủi ro cao (POST), yêu cầu duyệt sẽ xuất hiện trên <b>HÀNG ĐỢI PHÊ DUYỆT (Sidebar)</b> để bạn tương tác duyệt thời gian thực (120s Fail-Safe).
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        time.sleep(1.0)
        st.rerun()

    if runner_state.is_finished:
        if runner_state.error:
            st.error(f"Lỗi trong quá trình phân tích: {runner_state.error}")
        else:
            st.success(f"Phân tích hoàn tất thành công trong {runner_state.elapsed_seconds:.2f}s!")
        runner.reset()

    # Trigger Agent Analysis
    if btn_run_agent:
        if not selected_findings_file:
            st.error("Vui lòng chọn hoặc tải lên tệp Unified Findings.")
        elif runner_state.is_running:
            st.warning("Agent đang chạy một phiên phân tích khác. Vui lòng chờ hoàn tất.")
        else:
            started = runner.start(
                findings_path=selected_findings_file,
                model=model_name,
                agent_mode=agent_mode_sel,
                max_react_steps=max_steps_sel,
                approval_callback=hitl_mgr.request_in_flight_approval,
            )
            if started:
                st.toast("Đã khởi chạy phiên phân tích AI Agent!")
                st.rerun()

    st.divider()

    # Section 2: Load and Display Latest Report
    available_reports = list_analyzed_reports()
    if not available_reports:
        st.info("Chưa có báo cáo phân tích nào trong reports/analyzed/. Hãy khởi chạy Agent ở trên.")
    else:
        active_report_path = st.selectbox("Chọn báo cáo phân tích để xem:", available_reports, index=0)
        report_entries = load_analysis_report(active_report_path)

        if report_entries:
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

            for grp_id, items in groups_dict.items():
                first_item = items[0]
                corr_type = first_item.get("correlation_type", "sast_only")
                primary_cwe = first_item.get("primary_cwe_id") or "N/A"
                grp_title = first_item.get("title", "Lỗ hổng bảo mật")

                with st.expander(f"[{grp_id}] {grp_title} ({primary_cwe}) — {len(items)} findings | Tương quan: {corr_type.upper()}", expanded=True):
                    # Group Summary Header
                    st.markdown(
                        f"""
                        <div style="background: rgba(17, 25, 39, 0.7); border-radius: 10px; padding: 12px; margin-bottom: 12px; border: 1px solid rgba(255,255,255,0.06);">
                            <div style="display: flex; gap: 8px; margin-bottom: 6px;">
                                <span class="bento-badge info">CWE: {primary_cwe}</span>
                                <span class="bento-badge default">Correlation: {corr_type}</span>
                                <span class="bento-badge success">Confidence: {first_item.get('confidence', {}).get('level', 'unknown').upper()}</span>
                            </div>
                            <div style="font-size: 13px; color: #cdd6f4;">
                                <b>Nguyên nhân gốc (Root Cause):</b> {first_item.get('explanation')}
                            </div>
                            <div style="font-size: 13px; color: #10B981; margin-top: 4px;">
                                <b>Đề xuất khắc phục (Remediation):</b> {first_item.get('recommended_action')}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    # Nested Sub-Table for Findings in Group
                    for idx, finding in enumerate(items, 1):
                        st.markdown(f"**Finding #{idx}: `{finding.get('finding_id')}` | Công cụ: `{finding.get('tool')}` ({finding.get('scan_type')})**")
                        c_loc, c_sev, c_ev = st.columns([1, 1, 2])
                        with c_loc:
                            st.caption(f"**Vị trí:** {finding.get('location_summary')}")
                            st.caption(f"**Fingerprint:** `{finding.get('fingerprint', '')[:20]}...`")
                        with c_sev:
                            sev = finding.get("severity", {})
                            st.caption(f"**Severity:** Agent `{sev.get('agent_assessment')}` | Gốc `{sev.get('original_scanner')}`")
                            st.caption(f"**Status:** `{finding.get('analysis_status')}`")
                        with c_ev:
                            st.caption(f"**Bằng chứng:** {finding.get('evidence_summary')}")

                        # Proposed Test Request & HITL Dispatch
                        ptr = finding.get("proposed_test_request")
                        if ptr:
                            st.markdown(
                                f"""
                                <div style="background: rgba(250, 179, 135, 0.1); border-left: 3px solid #fab387; padding: 8px 12px; border-radius: 6px; font-size: 12px; margin: 6px 0;">
                                    <b>Đề xuất kiểm thử an toàn:</b> <code>{ptr.get('method')} {ptr.get('endpoint')}</code> | <i>{ptr.get('rationale')}</i>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                            if st.button(f"Đẩy vào HITL Queue ({finding.get('finding_id', '')[:8]})", key=f"btn_q_{finding.get('finding_id')}"):
                                req_id = hitl_mgr.add_action(
                                    endpoint=ptr.get("endpoint", "/"),
                                    method=ptr.get("method", "GET"),
                                    payload=ptr.get("payload"),
                                    headers=ptr.get("headers"),
                                    rationale=ptr.get("rationale", ""),
                                )
                                st.success(f"Đã thêm vào hàng đợi HITL với mã #{req_id}!")
                                st.rerun()

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
                    st.markdown(
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
                        """,
                        unsafe_allow_html=True,
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

                    st.markdown(
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
                        """,
                        unsafe_allow_html=True,
                    )
                with st.expander("Xem toàn văn log thô (Raw JSONL Trace)", expanded=False):
                    preview_log = "\n".join(lines[-30:]) if lines else "File log trống."
                    render_realtime_log_box(preview_log, max_height="260px")
            else:
                preview_log = "\n".join(lines[-30:]) if lines else "File log trống."
                render_realtime_log_box(preview_log, max_height="320px")
