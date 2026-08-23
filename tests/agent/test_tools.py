"""Unit tests for Project Sentinel ReAct Agent Tool Registry and Dispatcher."""

from typing import Any
from unittest.mock import MagicMock, patch

from src.agent.tools import (
    AGENT_TOOLS,
    ToolDispatcher,
)
from src.retrieval.service import KnowledgeSearchService, SearchResult


def test_agent_tools_schema_validity() -> None:
    """Verify that AGENT_TOOLS contains 4 valid OpenAI-compatible tool definitions."""
    assert isinstance(AGENT_TOOLS, list)
    assert len(AGENT_TOOLS) == 4

    tool_names = {t["function"]["name"] for t in AGENT_TOOLS}
    expected_names = {
        "search_knowledge_base",
        "get_knowledge_document",
        "lookup_safe_payloads",
        "send_safe_request",
    }
    assert tool_names == expected_names

    for tool in AGENT_TOOLS:
        assert tool["type"] == "function"
        fn = tool["function"]
        assert "name" in fn
        assert "description" in fn
        assert "parameters" in fn
        assert fn["parameters"]["type"] == "object"
        assert "required" in fn["parameters"]


def test_dispatcher_lookup_safe_payloads() -> None:
    """Verify lookup_safe_payloads returns payload list from catalog."""
    dispatcher = ToolDispatcher()
    result = dispatcher.execute("lookup_safe_payloads", {"category": "sql_injection_probes"})
    assert result["status"] == "success"
    assert result["category"] == "sql_injection_probes"
    assert isinstance(result["payloads"], list)
    assert len(result["payloads"]) > 0
    assert any("'" in p for p in result["payloads"])


def test_dispatcher_lookup_safe_payloads_invalid_category() -> None:
    """Verify lookup_safe_payloads handles unknown category gracefully."""
    dispatcher = ToolDispatcher()
    result = dispatcher.execute("lookup_safe_payloads", {"category": "non_existent_category"})
    assert result["status"] == "error"
    assert "non_existent_category" in result["message"]


def test_dispatcher_search_knowledge_base() -> None:
    """Verify search_knowledge_base executes search and returns snippets."""
    mock_kb = MagicMock(spec=KnowledgeSearchService)
    mock_kb.search.return_value = [
        SearchResult(
            doc_id="cwe-89",
            doc_type="cwe",
            title="CWE-89: SQL Injection",
            snippet="Improper neutralization of special elements in SQL command",
            summary="SQL injection vulnerability overview",
            aliases=["SQLi"],
            identifiers={"cwe": ["CWE-89"]},
            tags=["injection", "sql"],
            score=12.5,
        )
    ]

    dispatcher = ToolDispatcher(kb_service=mock_kb)
    result = dispatcher.execute("search_knowledge_base", {"query": "SQL Injection", "mode": "hybrid", "top_k": 1})

    assert result["status"] == "success"
    assert result["total_results"] == 1
    assert result["results"][0]["doc_id"] == "cwe-89"
    assert "SQL Injection" in result["results"][0]["title"]
    mock_kb.search.assert_called_once_with(query="SQL Injection", mode="hybrid", top_k=1)


def test_dispatcher_get_knowledge_document() -> None:
    """Verify get_knowledge_document fetches single document details."""
    mock_kb = MagicMock(spec=KnowledgeSearchService)
    mock_doc = MagicMock()
    mock_doc.doc_id = "cwe-89"
    mock_doc.title = "CWE-89: SQL Injection"
    mock_doc.summary = "Summary of SQL Injection"
    mock_doc.content = "Detailed content about SQL Injection vulnerability and remediation."
    mock_doc.aliases = ["SQLi"]
    mock_doc.tags = ["injection"]
    mock_kb.get_document.return_value = mock_doc

    dispatcher = ToolDispatcher(kb_service=mock_kb)
    result = dispatcher.execute("get_knowledge_document", {"doc_id": "cwe-89"})

    assert result["status"] == "success"
    assert result["document"]["doc_id"] == "cwe-89"
    assert "Detailed content" in result["document"]["content_preview"]
    mock_kb.get_document.assert_called_once_with(doc_id="cwe-89")


def test_dispatcher_send_safe_request() -> None:
    """Verify send_safe_request dispatches to safe_requester."""
    with patch("src.agent.tools.send_safe_request_core") as mock_req:
        mock_req.return_value = {
            "status_code": 200,
            "endpoint": "/rest/products/search?q=apple",
            "method": "GET",
            "headers": {"content-type": "application/json"},
            "body": "<untrusted_http_response>{\"data\":[]}</untrusted_http_response>",
            "truncated": False,
            "duration_ms": 45.2,
        }

        dispatcher = ToolDispatcher()
        result = dispatcher.execute(
            "send_safe_request",
            {
                "endpoint": "/rest/products/search?q=apple",
                "method": "GET",
                "payload_category": "special_chars",
            },
        )

        assert result["status_code"] == 200
        assert result["endpoint"] == "/rest/products/search?q=apple"
        assert "<untrusted_http_response>" in result["body"]
        mock_req.assert_called_once()


def test_dispatcher_repetitive_action_guard() -> None:
    """Verify dispatcher detects and prevents repeated identical tool calls."""
    dispatcher = ToolDispatcher(max_repeat_tool_calls=2)

    # First call: OK
    r1 = dispatcher.execute("lookup_safe_payloads", {"category": "empty_values"})
    assert r1["status"] == "success"

    # Second call with same args: OK
    r2 = dispatcher.execute("lookup_safe_payloads", {"category": "empty_values"})
    assert r2["status"] == "success"

    # Third call with same args: Blocked by Repetitive Action Guard
    r3 = dispatcher.execute("lookup_safe_payloads", {"category": "empty_values"})
    assert r3["status"] == "warning"
    assert "Hành động này đã được thực hiện trước đó" in r3["message"]


def test_dispatcher_unknown_tool() -> None:
    """Verify dispatcher returns error for unregistered tool name."""
    dispatcher = ToolDispatcher()
    result = dispatcher.execute("execute_arbitrary_code", {"cmd": "rm -rf /"})
    assert result["status"] == "error"
    assert "Unknown tool" in result["message"]


def test_dispatcher_hitl_rejection_interception() -> None:
    """Verify that when HITL callback rejects an action, probe returns rejected observation."""
    # Callback simulates operator rejection
    def mock_hitl_reject(assessment: dict[str, Any]) -> bool:
        return False

    dispatcher = ToolDispatcher(approval_callback=mock_hitl_reject)

    with patch("src.gateway.safe_requester.log_audit_event"):
        # POST method requires HITL approval
        res = dispatcher.execute(
            "send_safe_request",
            {"endpoint": "/rest/products/1/reviews", "method": "POST", "payload_category": "special_chars"},
        )
        assert res["status"] == "rejected"
        assert "rejected by human operator" in res["message"]
        assert "HITL REJECTED" in res["body"]


def test_dispatcher_hitl_approval_interception() -> None:
    """Verify that when HITL callback approves an action, probe proceeds to execute."""
    def mock_hitl_approve(assessment: dict[str, Any]) -> bool:
        return True

    dispatcher = ToolDispatcher(approval_callback=mock_hitl_approve)

    with patch("src.gateway.safe_requester._execute_single_http_request") as mock_exec:
        mock_exec.return_value = {
            "status": "success",
            "status_code": 200,
            "endpoint": "/rest/products/1/reviews",
            "method": "POST",
            "headers": {},
            "body": "<untrusted_http_response>success</untrusted_http_response>",
            "truncated": False,
            "duration_ms": 45.0,
        }
        res = dispatcher.execute(
            "send_safe_request",
            {"endpoint": "/rest/products/1/reviews", "method": "POST", "payload_category": "special_chars"},
        )
        assert res["status_code"] == 200
        mock_exec.assert_called_once()
