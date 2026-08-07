"""Trang Tra cứu Kiến thức Bảo mật (Security Knowledge Base Search)."""

import sys
from pathlib import Path

# Ensure project root is in sys.path for Streamlit execution
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st

from frontend.components.cards import render_badge, render_section_header
from src.app.retrieval_bridge import (
    get_supported_doc_types,
    inspect_knowledge_document,
    search_knowledge_base,
)

st.set_page_config(page_title="Knowledge Base - Sentinel", page_icon="📚", layout="wide")

st.title("📚 Tra cứu Tri thức An toàn (Security Knowledge Base)")
st.caption("Truy hồi thông tin bảo mật từ hơn 442 canonical documents (CWE, OWASP Top 10) sử dụng SQLite FTS5 Search Engine.")

render_section_header("Tìm kiếm Tri thức An ninh Mạng", "Nhập từ khóa lỗ hổng, mã CWE hoặc danh mục OWASP")

col_query, col_type, col_topk = st.columns([3, 1.5, 1])

with col_query:
    query = st.text_input("Từ khóa tìm kiếm (Query):", value="SQL Injection", placeholder="Ví dụ: SQL Injection, CWE-89, XSS, Broken Auth...")

with col_type:
    doc_types = ["All"] + get_supported_doc_types()
    selected_doc_type = st.selectbox("Loại tài liệu (Doc Type):", options=doc_types)

with col_topk:
    top_k = st.number_input("Số lượng kết quả (Top K):", min_value=1, max_value=50, value=5)

if query.strip():
    filter_type = None if selected_doc_type == "All" else selected_doc_type
    try:
        results = search_knowledge_base(query=query, doc_type=filter_type, top_k=top_k)
        
        st.markdown(f"### 🔍 Tìm thấy `{len(results)}` kết quả phù hợp cho: *'{query}'*")
        st.divider()

        if not results:
            st.info("Không tìm thấy tài liệu phù hợp. Hãy thử từ khóa khác (ví dụ: 'SQLi', 'CWE89', 'XSS').")
        
        for idx, item in enumerate(results, 1):
            with st.container():
                col_info, col_action = st.columns([4, 1])
                with col_info:
                    st.markdown(f"#### {idx}. {item.get('title')} (`{item.get('doc_id')}`)")
                    render_badge(item.get("doc_type", "doc"), variant="info")
                    if item.get("bm25_score"):
                        st.caption(f"BM25 Score: {item.get('bm25_score'):.4f} | Rank: {item.get('exact_match_rank')}")
                    
                    st.markdown(f"**Tóm tắt:** {item.get('summary', 'Không có tóm tắt')}")
                    if item.get("snippet"):
                        st.markdown(f"**Trích dẫn (Snippet):** {item.get('snippet')}", unsafe_allow_html=True)
                
                with col_action:
                    st.write(" ")
                    if st.button("👁️ Chi tiết", key=f"inspect_{item.get('doc_id')}_{idx}"):
                        st.session_state[f"show_detail_{item.get('doc_id')}"] = True
                
                # Hiển thị chi tiết nếu bấm nút
                if st.session_state.get(f"show_detail_{item.get('doc_id')}"):
                    doc_detail = inspect_knowledge_document(item.get('doc_id'))
                    if doc_detail:
                        with st.expander(f"📄 Nội dung chi tiết: {item.get('doc_id')}", expanded=True):
                            st.json(doc_detail)

                st.divider()

    except Exception as exc:  # noqa: BLE001
        st.error(f"Lỗi khi tra cứu Knowledge Base: {exc}")
