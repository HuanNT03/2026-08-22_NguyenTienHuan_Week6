"""Trang Báo cáo An toàn AI Security Analysis Dashboard (Week 3 Agent)."""

import sys
from pathlib import Path

# Ensure project root is in sys.path for Streamlit execution
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st

from frontend.components.cards import render_badge, render_metric_card, render_section_header
from src.app.agent_bridge import (
    list_analyzed_reports,
    load_analysis_report,
    run_agent_analysis,
)
from src.app.normalizer_bridge import list_normalized_files
from src.app.retrieval_bridge import inspect_knowledge_document

st.set_page_config(page_title="AI Analysis Dashboard - Sentinel", page_icon="🤖", layout="wide")

st.title("🤖 AI Security Analysis Dashboard")
st.caption("Báo cáo phân tích an toàn thông tin tự động bằng Security Analysis Agent (LLM + Redaction + KB Provenance).")

tab_run, tab_view = st.tabs(["🚀 Khởi chạy AI Agent Phân tích", "📊 Xem Báo cáo Dashboard"])

# TAB 1: RUN AGENT
with tab_run:
    render_section_header("Kích hoạt Security Analysis Agent", "Phân tích file Unified Findings JSONL đã chuẩn hóa")
    
    normalized_files = list_normalized_files()
    if not normalized_files:
        st.warning("Chưa tìm thấy tập tin Unified Findings nào trong `reports/normalized/`. Vui lòng sang trang 1 để chạy Normalize trước.")
    else:
        selected_findings = st.selectbox("Chọn tập tin Unified Findings để phân tích:", options=normalized_files)
        model_name = st.text_input("Tên mô hình LLM (Model Name):", value="qwen-plus", help="Mặc định qwen-plus hoặc model đã cấu hình trong .env")

        if st.button("🚀 Chạy AI Analysis Agent", type="primary"):
            with st.spinner("Security Analysis Agent đang thực thi pipeline 3 giai đoạn (Grouping -> KB Search -> LLM Synthesis)..."):
                success, result_summary = run_agent_analysis(findings_path=selected_findings, model=model_name)
                if success:
                    st.success("Phân tích AI hoàn tất 100% coverage!")
                    st.json(result_summary)
                    st.info("Hãy chuyển sang tab '📊 Xem Báo cáo Dashboard' để kiểm tra kết quả chi tiết!")
                else:
                    st.error(f"Lỗi khi thực thi Agent: {result_summary.get('error')}")

# TAB 2: DASHBOARD VIEW
with tab_view:
    render_section_header("Báo cáo An toàn Đa chiều (Security Analysis Report)", "Trực quan hóa kết quả phân tích theo security_analysis_report.schema.json")

    analyzed_reports = list_analyzed_reports()
    if not analyzed_reports:
        st.info("Chưa có báo cáo phân tích nào trong `reports/analyzed/`. Vui lòng chạy AI Agent ở tab bên cạnh.")
    else:
        selected_report = st.selectbox("Chọn tập tin Báo cáo AI:", options=analyzed_reports)
        if selected_report:
            try:
                entries = load_analysis_report(selected_report)
                st.markdown(f"**Tổng số phát hiện trong báo cáo:** `{len(entries)}` entries")
                
                # --- CARD 1: EXECUTIVE THREAT OVERVIEW ---
                st.markdown("### 🟢 1. Executive Threat Overview (Tổng quan Rủi ro)")
                
                crit_high = sum(1 for e in entries if e.get("severity", {}).get("agent_assessment") in ("critical", "high"))
                fps = sum(1 for e in entries if e.get("confidence", {}).get("level") == "false_positive")
                confirmed = sum(1 for e in entries if e.get("correlation_type") == "sast_dast_confirmed")
                
                m1, m2, m3, m4 = st.columns(4)
                with m1:
                    render_metric_card("Tổng số Findings", str(len(entries)), "Phân tích 100% coverage")
                with m2:
                    render_metric_card("Critical / High Risk", str(crit_high), "Đánh giá bởi AI Agent")
                with m3:
                    render_metric_card("False Positives", str(fps), "Số báo nhầm đã phát hiện")
                with m4:
                    render_metric_card("SAST+DAST Confirmed", str(confirmed), "Lỗ hổng đã được xác nhận chéo")

                st.divider()

                # --- CARD 2: VULNERABILITY GROUPS LIST ---
                st.markdown("### 🟡 2. Vulnerability Groups & Locations (Danh sách Nhóm Lỗ hổng)")
                
                for idx, entry in enumerate(entries, 1):
                    with st.expander(f"📌 [{entry.get('severity', {}).get('agent_assessment', 'unknown').upper()}] {entry.get('title')} ({entry.get('analysis_group_id')})", expanded=(idx == 1)):
                        
                        col_meta, col_body = st.columns([1.5, 3])
                        
                        with col_meta:
                            st.markdown("#### Meta Data Badges")
                            render_badge(f"Tool: {entry.get('tool', '').upper()}", "default")
                            render_badge(f"Scan: {entry.get('scan_type', '')}", "info")
                            render_badge(f"CWE: {entry.get('primary_cwe_id', 'N/A')}", "critical")
                            if entry.get("owasp_category"):
                                render_badge(f"OWASP: {entry.get('owasp_category')}", "high")
                            
                            st.markdown(f"**Location:** `{entry.get('location_summary', 'N/A')}`")
                            st.markdown(f"**Correlation:** `{entry.get('correlation_type', 'N/A')}`")
                            st.markdown(f"**Fingerprint:** `{entry.get('fingerprint', '')[:25]}...`")

                        with col_body:
                            # --- CARD 3: ROOT CAUSE & RISK RATIONALE ---
                            st.markdown("#### 🔴 3. Root Cause & Risk Rationale (Nguyên nhân & Đánh giá)")
                            st.markdown(f"**Giải thích chi tiết (Explanation):**\n{entry.get('explanation', 'N/A')}")
                            st.markdown(f"**Tóm tắt Bằng chứng (Evidence Summary):**\n`{entry.get('evidence_summary', 'N/A')}`")
                            
                            sev_obj = entry.get("severity", {})
                            st.info(f"**Scanner Severity:** `{sev_obj.get('original_scanner')}` | **Agent Assessment:** `{sev_obj.get('agent_assessment')}`\n\n**Severity Rationale:** {sev_obj.get('rationale')}")

                            conf_obj = entry.get("confidence", {})
                            st.caption(f"**Confidence Level:** `{conf_obj.get('level')}` | **Rationale:** {conf_obj.get('rationale')}")

                            # --- CARD 4: STEP-BY-STEP REMEDIATION ---
                            st.markdown("#### 🔵 4. Step-by-Step Remediation (Hướng dẫn Vá lỗi)")
                            st.success(f"**Hành động khuyến nghị (Recommended Action):**\n{entry.get('recommended_action', 'N/A')}")

                            req = entry.get("proposed_test_request")
                            if req:
                                st.warning("**Safe Dynamic Verification Request (Yêu cầu Kiểm thử An toàn):**")
                                st.code(f"{req.get('method')} {req.get('endpoint')}\nHeaders: {req.get('headers')}\nPayload: {req.get('payload')}", language="json")
                                st.caption(f"Rationale: {req.get('rationale')}")

                            # --- CARD 5: KB PROVENANCE & CITATION ---
                            st.markdown("#### 🟣 5. Knowledge References & Citation (Trích dẫn KB)")
                            refs = entry.get("knowledge_references", [])
                            if refs:
                                for ref in refs:
                                    st.markdown(f"- 📖 **[{ref.get('doc_id')}]** {ref.get('title')} — *{ref.get('relevance')}*")
                                    if st.button(f"Xem bài viết KB ({ref.get('doc_id')})", key=f"kb_ref_{ref.get('doc_id')}_{idx}"):
                                        kb_doc = inspect_knowledge_document(ref.get("doc_id"))
                                        if kb_doc:
                                            st.json(kb_doc)
                            else:
                                st.text("Không có trích dẫn KB trực tiếp.")

            except Exception as exc:  # noqa: BLE001
                st.error(f"Lỗi khi tải báo cáo AI Analysis: {exc}")
