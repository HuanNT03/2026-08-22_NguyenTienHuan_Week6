"""Tool Registry and Execution Dispatcher for Project Sentinel ReAct Security Agent.

This module declares the 4 OpenAI-compatible tools available to the Security Analysis
Agent, provides argument schema validation, enforces Repetitive Action Guard to prevent
infinite execution loops, and ensures 2-way guardrails sanitization.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.gateway.safe_requester import send_safe_request as send_safe_request_core
from src.retrieval.service import KnowledgeSearchService

logger = logging.getLogger(__name__)

PAYLOADS_CATALOG_PATH = Path(__file__).resolve().parent.parent / "gateway" / "payloads.json"

AGENT_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "search_knowledge_base",
            "description": (
                "Tìm kiếm tri thức bảo mật chuẩn hóa trong Knowledge Base (CWE, OWASP Top 10, "
                "nguyên nhân gốc, và khuyến nghị khắc phục). Hỗ trợ chế độ hybrid (FTS5 + Qdrant)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Từ khóa hoặc câu hỏi kỹ thuật (Ví dụ: 'CWE-89 SQL Injection', 'reflected XSS remediation', 'CWE-200').",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["hybrid", "keyword", "semantic"],
                        "default": "hybrid",
                        "description": "Chế độ tìm kiếm: 'hybrid' (kết hợp FTS5 và Vector), 'keyword' (BM25), hoặc 'semantic' (Dense Vector).",
                    },
                    "top_k": {
                        "type": "integer",
                        "default": 3,
                        "description": "Số lượng tài liệu liên quan nhất cần trả về (1 đến 5).",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_knowledge_document",
            "description": "Lấy toàn bộ nội dung chi tiết của một tài liệu tri thức dựa trên mã doc_id cụ thể (Ví dụ: 'cwe-89', 'owasp-2025-a01').",
            "parameters": {
                "type": "object",
                "properties": {
                    "doc_id": {
                        "type": "string",
                        "description": "Mã định danh duy nhất của tài liệu tri thức (Ví dụ: 'cwe-89', 'cwe-79', 'owasp-2025-a03').",
                    },
                },
                "required": ["doc_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_safe_payloads",
            "description": (
                "Tra cứu các mẫu probe payload kiểm thử an toàn đã được kiểm duyệt trong catalog chuẩn "
                "(src/gateway/payloads.json) theo từng phân loại (sql_injection_probes, special_chars, long_string,...)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": [
                            "long_string",
                            "special_chars",
                            "empty_values",
                            "type_mismatch",
                            "query_param_injection",
                            "sql_injection_probes",
                            "cross_site_scripting_probes",
                        ],
                        "description": "Nhóm payload an toàn cần tra cứu từ catalog.",
                    },
                },
                "required": ["category"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_safe_request",
            "description": (
                "Gửi HTTP request kiểm thử an toàn qua Kong API Gateway (Port 3000) vào ứng dụng đích để xác minh "
                "lỗ hổng thời gian thực. Hỗ trợ GET, PUT, OPTIONS. Tự động kích hoạt HITL khi có rủi ro và "
                "tự động khử khuẩn PII & bọc chống Prompt Injection trong thẻ <untrusted_http_response>."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoint": {
                        "type": "string",
                        "description": "Endpoint path cần kiểm thử (bắt đầu bằng '/', ví dụ: '/rest/products/search?q=apple', '/api/Products').",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "PUT", "OPTIONS"],
                        "default": "GET",
                        "description": "Phương thức HTTP được phép theo chính sách an toàn.",
                    },
                    "payload_category": {
                        "type": "string",
                        "enum": [
                            "long_string",
                            "special_chars",
                            "empty_values",
                            "type_mismatch",
                            "query_param_injection",
                            "sql_injection_probes",
                            "cross_site_scripting_probes",
                        ],
                        "description": "Nhóm payload an toàn nạp từ catalog.",
                    },
                    "payload_value": {
                        "type": "string",
                        "description": "Giá trị payload cụ thể tùy chỉnh gửi trong request body hoặc query parameter.",
                    },
                    "burst_count": {
                        "type": "integer",
                        "default": 1,
                        "description": "Số lượng request gửi liên tiếp để kiểm tra Rate Limiting (429 Too Many Requests).",
                    },
                    "oversized_payload": {
                        "type": "boolean",
                        "default": False,
                        "description": "Nếu True, tự động sinh buffer 1.5MB để kiểm thử giới hạn kích thước gói tin Gateway.",
                    },
                },
                "required": ["endpoint"],
            },
        },
    },
]


class ToolDispatcher:
    """Dispatches tool calls requested by ReAct Agent with Loop Guards and sanitization."""

    def __init__(
        self,
        kb_service: KnowledgeSearchService | None = None,
        max_repeat_tool_calls: int = 2,
    ) -> None:
        """Initialize ToolDispatcher with knowledge service and loop repetition thresholds.

        Args:
            kb_service: Optional instance of KnowledgeSearchService. If None, lazy initialized.
            max_repeat_tool_calls: Maximum identical tool calls permitted before blocking.
        """
        self._kb_service = kb_service
        self.max_repeat_tool_calls = max_repeat_tool_calls
        self.call_history: list[tuple[str, str]] = []

    @property
    def kb_service(self) -> KnowledgeSearchService:
        """Lazy-loaded KnowledgeSearchService instance."""
        if self._kb_service is None:
            self._kb_service = KnowledgeSearchService()
        return self._kb_service

    def reset_history(self) -> None:
        """Clear recorded tool call history for a new AnalysisGroup session."""
        self.call_history.clear()

    def execute(self, tool_name: str, arguments: dict[str, Any] | str) -> dict[str, Any]:
        """Execute a tool call with Repetitive Action Guard and error handling.

        Args:
            tool_name: Name of the tool to execute.
            arguments: Dictionary or JSON string of arguments for the tool.

        Returns:
            dict[str, Any]: Execution result dictionary or structured warning/error object.
        """
        parsed_args: dict[str, Any] = {}
        if isinstance(arguments, str):
            try:
                parsed_args = json.loads(arguments) if arguments.strip() else {}
            except json.JSONDecodeError as err:
                return {
                    "status": "error",
                    "message": f"Malformed tool arguments JSON: {err}",
                }
        elif isinstance(arguments, dict):
            parsed_args = arguments

        # 1. Repetitive Action Guard Check
        canonical_args_str = json.dumps(parsed_args, sort_keys=True)
        repeat_count = sum(
            1 for name, args_str in self.call_history if name == tool_name and args_str == canonical_args_str
        )

        if repeat_count >= self.max_repeat_tool_calls:
            logger.warning(
                "Repetitive action blocked for tool %r with args %s (count: %d)",
                tool_name,
                canonical_args_str,
                repeat_count,
            )
            return {
                "status": "warning",
                "message": (
                    f"Hành động này đã được thực hiện trước đó với cùng tham số ({repeat_count} lần). "
                    "Không được lặp lại. Hãy suy luận dựa trên quan sát đã thu thập và chuyển sang kết luận."
                ),
            }

        self.call_history.append((tool_name, canonical_args_str))

        # 2. Dispatch to specific tool handler
        try:
            if tool_name == "search_knowledge_base":
                return self._handle_search_knowledge_base(parsed_args)
            elif tool_name == "get_knowledge_document":
                return self._handle_get_knowledge_document(parsed_args)
            elif tool_name == "lookup_safe_payloads":
                return self._handle_lookup_safe_payloads(parsed_args)
            elif tool_name == "send_safe_request":
                return self._handle_send_safe_request(parsed_args)
            else:
                return {
                    "status": "error",
                    "message": f"Unknown tool '{tool_name}'. Available tools: {[t['function']['name'] for t in AGENT_TOOLS]}",
                }
        except Exception as err:  # noqa: BLE001
            logger.error("Tool execution failed for %r: %s", tool_name, err, exc_info=True)
            return {
                "status": "error",
                "message": f"Lỗi khi thực thi công cụ '{tool_name}': {err}",
            }

    def _handle_search_knowledge_base(self, args: dict[str, Any]) -> dict[str, Any]:
        """Execute knowledge search via KnowledgeSearchService."""
        query = str(args.get("query", "")).strip()
        if not query:
            return {"status": "error", "message": "Tham số 'query' không được để trống."}

        mode = args.get("mode", "hybrid")
        top_k = min(5, max(1, int(args.get("top_k", 3))))

        results = self.kb_service.search(query=query, mode=mode, top_k=top_k)
        formatted_results = [
            {
                "doc_id": r.doc_id,
                "doc_type": r.doc_type,
                "title": r.title,
                "summary": r.summary,
                "snippet": r.snippet,
                "tags": r.tags,
                "score": round(r.score, 4),
            }
            for r in results
        ]

        return {
            "status": "success",
            "query": query,
            "mode": mode,
            "total_results": len(formatted_results),
            "results": formatted_results,
        }

    def _handle_get_knowledge_document(self, args: dict[str, Any]) -> dict[str, Any]:
        """Fetch full details of a specific knowledge document by ID."""
        doc_id = str(args.get("doc_id", "")).strip()
        if not doc_id:
            return {"status": "error", "message": "Tham số 'doc_id' không được để trống."}

        doc = self.kb_service.get_document(doc_id=doc_id)
        if doc is None:
            return {
                "status": "not_found",
                "message": f"Không tìm thấy tài liệu tri thức với doc_id='{doc_id}'.",
            }

        # Truncate content preview to 1500 chars to avoid blowing up context window
        content_preview = doc.content[:1500] if doc.content else ""
        if len(doc.content or "") > 1500:
            content_preview += "\n... [Nội dung đã được cắt bớt để tối ưu ngữ cảnh]"

        return {
            "status": "success",
            "document": {
                "doc_id": doc.doc_id,
                "doc_type": doc.doc_type,
                "title": doc.title,
                "summary": doc.summary,
                "aliases": doc.aliases,
                "tags": doc.tags,
                "content_preview": content_preview,
            },
        }

    def _handle_lookup_safe_payloads(self, args: dict[str, Any]) -> dict[str, Any]:
        """Read safe payload list from payloads.json catalog."""
        category = str(args.get("category", "")).strip()
        if not category:
            return {"status": "error", "message": "Tham số 'category' không được để trống."}

        if not PAYLOADS_CATALOG_PATH.is_file():
            return {
                "status": "error",
                "message": f"Không tìm thấy catalog payload tại {PAYLOADS_CATALOG_PATH}.",
            }

        try:
            catalog = json.loads(PAYLOADS_CATALOG_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError as err:
            return {"status": "error", "message": f"Lỗi đọc catalog payloads.json: {err}"}

        if category not in catalog:
            valid_cats = [k for k in catalog.keys() if k != "description"]
            return {
                "status": "error",
                "message": f"Category '{category}' không hợp lệ. Các category được phép: {valid_cats}",
            }

        payloads = catalog[category]
        return {
            "status": "success",
            "category": category,
            "payloads": payloads if isinstance(payloads, list) else [payloads],
        }

    def _handle_send_safe_request(self, args: dict[str, Any]) -> dict[str, Any]:
        """Send safe HTTP request via Safe Requester through Kong API Gateway."""
        endpoint = str(args.get("endpoint", "")).strip()
        if not endpoint or not endpoint.startswith("/"):
            return {"status": "error", "message": "Tham số 'endpoint' phải bắt đầu bằng '/'."}

        method = str(args.get("method", "GET")).strip().upper()
        payload_category = args.get("payload_category")
        payload_value = args.get("payload_value")
        burst_count = int(args.get("burst_count", 1))
        oversized_payload = bool(args.get("oversized_payload", False))

        result = send_safe_request_core(
            endpoint=endpoint,
            method=method,
            payload_category=payload_category,
            payload_value=payload_value,
            burst_count=burst_count,
            oversized_payload=oversized_payload,
        )

        return result
