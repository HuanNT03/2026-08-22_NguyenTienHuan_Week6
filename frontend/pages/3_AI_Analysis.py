"""Trang Báo cáo An toàn AI Security Analysis Dashboard (Bento Box Enhanced)."""

from collections import defaultdict
from pathlib import Path
import sys

# Ensure project root is in sys.path for Streamlit execution
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st

from frontend.components.bento import (
    inject_bento_css,
    render_bento_card,
    render_bento_header,
)
from frontend.components.cards import render_badge
from src.app.agent_bridge import (
    get_configured_model,
    list_analyzed_reports,
    load_analysis_report,
    run_agent_analysis,
)
from src.app.normalizer_bridge import list_normalized_files
from src.app.retrieval_bridge import inspect_knowledge_document

st.set_page_config(page_title="AI Analysis Dashboard - Sentinel", page_icon="🤖", layout="wide")

# Inject Bento CSS
inject_bento_css()

st.title("🤖 AI Security Analysis Dashboard")
st.caption("Báo cáo phân tích an toàn thông tin tự động bằng Security Analysis Agent (LLM + Redaction + KB Provenance).")

tab_run, tab_view = st.tabs(["🚀 Khởi chạy AI Agent Phân tích", "📊 Xem Báo cáo Dashboard (Grouped View)"])

# ==========================================
# TAB 1: RUN AGENT
# ==========================================
with tab_run:
    render_bento_header("Kích hoạt Security Analysis Agent", "Phân tích file Unified Findings JSONL đã chuẩn hóa", icon="🚀")

    normalized_files = list_normalized_files()
    if not normalized_files:
        st.warning("Chưa tìm thấy tập tin Unified Findings nào trong `reports/normalized/`. Vui lòng sang trang 1 để chạy Normalize trước.")
    else:
        selected_findings = st.selectbox("Chọn tập tin Unified Findings để phân tích:", options=normalized_files)

        # Dynamic model loading from .env
        default_env_model = get_configured_model()

        model_input = st.text_input(
            "Tên mô hình LLM (Model Name):",
            value=default_env_model,
            help=f"Mô hình đang được cấu hình trong file .env hiện tại là '{default_env_model}'. Nhập tên mô hình khác nếu muốn thay đổi, hoặc để trống để sử dụng giá trị cấu hình trong .env.",
        )

        # Resolution logic: custom input -> .env model -> default fallback
        if model_input and model_input.strip():
            active_model = model_input.strip()
            if active_model == default_env_model:
                st.caption(f"📌 Đang sử dụng mô hình được cấu hình trong `.env`: **`{active_model}`**")
            else:
                st.caption(f"✏️ Đang sử dụng mô hình tùy chỉnh do người dùng nhập: **`{active_model}`** *(Cấu hình gốc trong .env: `{default_env_model}`)*")
        else:
            active_model = default_env_model or "qwen-plus"
            st.caption(f"🔄 Ô nhập để trống — Tự động fallback về mô hình trong `.env`: **`{active_model}`**")

        if st.button("🚀 Chạy AI Analysis Agent", type="primary"):
            with st.spinner(f"Security Analysis Agent đang thực thi pipeline bằng mô hình '{active_model}' (Grouping -> KB Search -> LLM Synthesis)..."):
                success, result_summary = run_agent_analysis(findings_path=selected_findings, model=active_model)
                if success:
                    st.success(f"Phân tích AI bằng mô hình '{active_model}' hoàn tất 100% coverage!")
                    st.json(result_summary)
                    st.info("Hãy chuyển sang tab '📊 Xem Báo cáo Dashboard' để kiểm tra kết quả chi tiết!")
                else:
                    st.error(f"Lỗi khi thực thi Agent: {result_summary.get('error')}")

# ==========================================
# TAB 2: DASHBOARD VIEW (GROUPED VULNERABILITY BENTO)
# ==========================================
with tab_view:
    render_bento_header("Security Analysis Report Dashboard", "Trực quan hóa kết quả phân tích theo nhóm lỗ hổng (Grouped View)", icon="📊")

    analyzed_reports = list_analyzed_reports()
    if not analyzed_reports:
        st.info("Chưa có báo cáo phân tích nào trong `reports/analyzed/`. Vui lòng chạy AI Agent ở tab bên cạnh.")
    else:
        # Selector for specific security-analysis-report-*.jsonl files
        selected_report = st.selectbox(
            "Chọn tập tin Báo cáo AI (security-analysis-report-*.jsonl):",
            options=analyzed_reports,
            format_func=lambda x: f"📄 {Path(x).name}",
        )

        if selected_report:
            try:
                entries = load_analysis_report(selected_report)
                
                # --- CARD 1: EXECUTIVE THREAT OVERVIEW ---
                crit_high = sum(1 for e in entries if e.get("severity", {}).get("agent_assessment") in ("critical", "high"))
                fps = sum(1 for e in entries if e.get("confidence", {}).get("level") == "false_positive")
                confirmed = sum(1 for e in entries if e.get("correlation_type") == "sast_dast_confirmed")

                m1, m2, m3, m4 = st.columns(4)
                with m1:
                    render_bento_card("Total Findings", str(len(entries)), "Phân tích 100% coverage", icon="📋", badge_text="Total", badge_variant="info")
                with m2:
                    render_bento_card("Critical / High Risk", str(crit_high), "Đánh giá bởi AI Agent", icon="🔥", badge_text="Severe", badge_variant="critical" if crit_high > 0 else "success")
                with m3:
                    render_bento_card("False Positives", str(fps), "Số báo nhầm đã phát hiện", icon="🛡️", badge_text="Filtered", badge_variant="medium" if fps > 0 else "default")
                with m4:
                    render_bento_card("SAST+DAST Confirmed", str(confirmed), "Xác nhận chéo 2 phương pháp", icon="🎯", badge_text="Confirmed", badge_variant="success" if confirmed > 0 else "info")

                st.divider()

                # --- CARD 2: VULNERABILITY GROUPS PRESENTATION (GROUPED VIEW) ---
                st.markdown("### 🟡 Danh sách Lỗ hổng theo Nhóm Phân tích (`Grouped View`)")
                st.caption("Các phát hiện có chung nguyên nhân hoặc `group_key` / `analysis_group_id` được gom nhóm để đánh giá tổng thể:")

                # Group entries by analysis_group_id
                grouped_entries: dict[str, list[dict]] = defaultdict(list)
                for entry in entries:
                    group_id = entry.get("analysis_group_id") or entry.get("group_key") or "group_unspecified"
                    grouped_entries[group_id].append(entry)

                st.markdown(f"Đã nhóm **{len(entries)}** phát hiện thành **{len(grouped_entries)}** cụm lỗ hổng chính.")

                for grp_idx, (group_id, group_items) in enumerate(grouped_entries.items(), 1):
                    # Determine highest severity in group
                    sev_levels = [item.get("severity", {}).get("agent_assessment", "unknown").lower() for item in group_items]
                    if "critical" in sev_levels:
                        top_sev = "critical"
                    elif "high" in sev_levels:
                        top_sev = "high"
                    elif "medium" in sev_levels:
                        top_sev = "medium"
                    elif "low" in sev_levels:
                        top_sev = "low"
                    else:
                        top_sev = "default"

                    group_title = group_items[0].get("title", f"Group {group_id}")
                    
                    with st.expander(
                        f"📌 Cụm #{grp_idx}: [{top_sev.upper()}] {group_title} — ({len(group_items)} findings in group ID: {group_id[:16]}...)",
                        expanded=(grp_idx == 1),
                    ):
                        st.markdown(
                            f"""
                            <div style="background: rgba(24, 24, 37, 0.7); padding: 12px 16px; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.05); margin-bottom: 16px;">
                                <div style="font-weight: 700; color: #cdd6f4; font-size: 16px;">Thẻ Tóm tắt Cụm Lỗ hổng (Group Bento Header)</div>
                                <div style="font-size: 13px; color: #a6adc8; margin-top: 4px;">Analysis Group ID: <code>{group_id}</code> | Tổng phát hiện gộp: <b>{len(group_items)}</b></div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                        for idx, entry in enumerate(group_items, 1):
                            st.markdown(f"#### 📄 Finding {idx}/{len(group_items)}: {entry.get('title')}")
                            
                            col_meta, col_body = st.columns([1.4, 2.6])

                            with col_meta:
                                st.markdown("**Metadata Badges:**")
                                render_badge(f"Tool: {entry.get('tool', '').upper()}", "default")
                                render_badge(f"Scan: {entry.get('scan_type', '')}", "info")
                                render_badge(f"CWE: {entry.get('primary_cwe_id', 'N/A')}", "critical")
                                if entry.get("owasp_category"):
                                    render_badge(f"OWASP: {entry.get('owasp_category')}", "high")

                                st.markdown(f"**Location:** `{entry.get('location_summary', 'N/A')}`")
                                st.markdown(f"**Correlation:** `{entry.get('correlation_type', 'N/A')}`")
                                st.markdown(f"**Fingerprint:** `{entry.get('fingerprint', '')[:20]}...`")

                            with col_body:
                                # Bento Sub-card 1: Root Cause & Rationale
                                st.markdown("##### 🔴 1. Root Cause & Rationale")
                                st.markdown(f"**Giải thích chi tiết:**\n{entry.get('explanation', 'N/A')}")
                                st.markdown(f"**Bằng chứng (Evidence Summary):**\n`{entry.get('evidence_summary', 'N/A')}`")

                                sev_obj = entry.get("severity", {})
                                st.info(f"**Scanner Severity:** `{sev_obj.get('original_scanner')}` | **Agent Assessment:** `{sev_obj.get('agent_assessment')}`\n\n**Rationale:** {sev_obj.get('rationale')}")

                                conf_obj = entry.get("confidence", {})
                                st.caption(f"**Confidence Level:** `{conf_obj.get('level')}` | Rationale: {conf_obj.get('rationale')}")

                                # Bento Sub-card 2: Step-by-step Remediation
                                st.markdown("##### 🔵 2. Step-by-Step Remediation & Safe Verification")
                                st.success(f"**Hành động khuyến nghị:**\n{entry.get('recommended_action', 'N/A')}")

                                req = entry.get("proposed_test_request")
                                if req:
                                    st.warning("**Yêu cầu Kiểm thử An toàn (Safe Dynamic Verification):**")
                                    st.code(
                                        f"{req.get('method')} {req.get('endpoint')}\nHeaders: {req.get('headers')}\nPayload: {req.get('payload')}",
                                        language="json",
                                    )
                                    st.caption(f"Rationale: {req.get('rationale')}")

                                # Bento Sub-card 3: KB Provenance & Citation
                                st.markdown("##### 🟣 3. Knowledge References & Citation")
                                refs = entry.get("knowledge_references", [])
                                if refs:
                                    for ref in refs:
                                        st.markdown(f"- 📖 **[{ref.get('doc_id')}]** {ref.get('title')} — *{ref.get('relevance')}*")
                                        if st.button(
                                            f"Xem chi tiết KB ({ref.get('doc_id')})",
                                            key=f"kb_ref_{ref.get('doc_id')}_{grp_idx}_{idx}",
                                        ):
                                            kb_doc = inspect_knowledge_document(ref.get("doc_id"))
                                            if kb_doc:
                                                st.json(kb_doc)
                                else:
                                    st.text("Không có trích dẫn KB trực tiếp.")

                            if idx < len(group_items):
                                st.divider()

            except Exception as exc:  # noqa: BLE001
                st.error(f"Lỗi khi tải báo cáo AI Analysis: {exc}")
