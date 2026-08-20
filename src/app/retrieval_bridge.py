"""Cầu nối tra cứu Knowledge Base SQLite FTS5 cho Web Application."""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from src.retrieval.config import DOCUMENT_TYPES, INDEX_PATH
from src.retrieval.exceptions import InvalidSearchQueryError
from src.retrieval.service import KnowledgeSearchService


def get_supported_doc_types() -> list[str]:
    """Trả về danh sách các document types được hỗ trợ."""
    return list(DOCUMENT_TYPES)


def search_knowledge_base(
    query: str,
    doc_type: str | None = None,
    top_k: int = 5,
    index_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """
    Thực thi tìm kiếm FTS5 trên Knowledge Base.

    Args:
        query: Từ khóa hoặc identifier cần tìm (vd: 'SQL Injection', 'CWE-89', 'XSS')
        doc_type: Loại tài liệu lọc (vd: 'cwe', 'owasp_category', 'vulnerability_example')
        top_k: Số lượng kết quả tối đa (1 đến 50)
        index_path: Tùy chọn đường dẫn file database SQLite

    Returns:
        list[dict]: Danh sách tài liệu kết quả đã sắp xếp
    """
    if not query or not query.strip():
        return []

    db_path = Path(index_path) if index_path else INDEX_PATH
    if not db_path.exists():
        raise FileNotFoundError(f"Database Knowledge Base không tồn tại tại: {db_path}. Vui lòng chạy 'make kb-build'.")

    service = KnowledgeSearchService(index_path=db_path)

    # Lọc bỏ doc_type không hợp lệ
    valid_doc_type = doc_type if doc_type in DOCUMENT_TYPES else None

    try:
        results = service.search(query=query.strip(), top_k=top_k, doc_type=valid_doc_type)
        return [asdict(res) for res in results]
    except InvalidSearchQueryError:
        return []
    except Exception as exc:
        raise RuntimeError(f"Lỗi khi tìm kiếm Knowledge Base: {exc}") from exc


def inspect_knowledge_document(doc_id: str, index_path: str | Path | None = None) -> dict[str, Any] | None:
    """
    Xem chi tiết 1 tài liệu canonical theo doc_id.

    Args:
        doc_id: ID tài liệu (vd: 'cwe-89', 'owasp-a03-2021')
        index_path: Tùy chọn đường dẫn SQLite index

    Returns:
        dict | None: Chi tiết tài liệu hoặc None nếu không tìm thấy
    """
    db_path = Path(index_path) if index_path else INDEX_PATH
    if not db_path.exists():
        return None

    import sqlite3

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM documents WHERE doc_id = ?", (doc_id,)).fetchone()
        conn.close()
        if not row:
            # Thử tìm kiếm theo FTS nếu doc_id không khớp tuyệt đối
            service = KnowledgeSearchService(index_path=db_path)
            results = service.search(query=doc_id, top_k=1)
            if results:
                return asdict(results[0])
            return None

        result_dict = dict(row)
        for field in ("aliases_json", "identifiers_json", "tags_json", "related_doc_ids_json"):
            if field in result_dict and isinstance(result_dict[field], str):
                try:
                    result_dict[field.replace("_json", "")] = json.loads(result_dict[field])
                except (json.JSONDecodeError, TypeError):
                    pass

        return result_dict
    except Exception:  # noqa: BLE001
        return None
