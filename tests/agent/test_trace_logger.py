"""Unit tests for Agent Execution Trace Logger and schema conformity."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from src.agent.trace_logger import TraceLogger

ROOT = Path(__file__).resolve().parents[2]
LOG_SCHEMA_PATH = ROOT / "schemas/agent_runner_log.schema.json"


def _get_validator() -> Draft202012Validator:
    schema = json.loads(LOG_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_trace_logger_span_generation_and_schema_conformity(tmp_path: Path) -> None:
    """Verify that TraceLogger generates valid spans matching agent_runner_log.schema.json."""
    validator = _get_validator()
    log_file = tmp_path / "test-agent-runner.log"
    logger = TraceLogger(log_file=log_file)

    # 1. Log LLM span
    span_llm = logger.log_span(
        group_id="grp_sqli_test",
        step_index=0,
        run_type="llm",
        name="qwen-plus",
        start_time=1724300000.0,
        end_time=1724300002.5,
        status="success",
        inputs={"messages": [{"role": "user", "content": "Analyze SQL Injection"}]},
        outputs={"thought": "Cần tra cứu KB", "tool_calls": [{"name": "search_knowledge_base", "arguments": "{}"}]},
        metadata={
            "model": "qwen-plus",
            "agent_mode": "react",
            "prompt_version": "system_v2",
            "temperature": 0.2,
            "max_steps": 5,
        },
        token_usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
    )
    errors = list(validator.iter_errors(span_llm))
    assert errors == []

    # 2. Log Tool span
    span_tool = logger.log_span(
        group_id="grp_sqli_test",
        step_index=0,
        run_type="tool",
        name="send_safe_request",
        start_time=1724300002.6,
        end_time=1724300003.1,
        status="success",
        inputs={"endpoint": "/rest/products/search?q=apple", "method": "GET"},
        outputs={"status_code": 200, "body": "Sanitized response"},
        metadata={
            "model": "qwen-plus",
            "agent_mode": "react",
            "prompt_version": "system_v2",
            "tool_name": "send_safe_request",
        },
    )
    errors = list(validator.iter_errors(span_tool))
    assert errors == []

    # 3. Log Chain span
    span_chain = logger.log_span(
        group_id="grp_sqli_test",
        step_index=0,
        run_type="chain",
        name="GroupAnalysisOrchestrator",
        start_time=1724300000.0,
        end_time=1724300005.0,
        status="success",
        inputs={"findings_count": 2},
        outputs={"entries_count": 2},
        metadata={
            "model": "qwen-plus",
            "agent_mode": "react",
            "prompt_version": "system_v2",
        },
    )
    errors = list(validator.iter_errors(span_chain))
    assert errors == []

    # 4. Verify file content
    assert log_file.is_file()
    lines = [json.loads(l) for l in log_file.read_text(encoding="utf-8").strip().splitlines()]
    assert len(lines) == 3
    for line in lines:
        assert list(validator.iter_errors(line)) == []


def test_trace_logger_redacts_sensitive_inputs(tmp_path: Path) -> None:
    """Verify that sensitive secrets and tokens are masked before logging."""
    log_file = tmp_path / "test-redact.log"
    logger = TraceLogger(log_file=log_file)

    span = logger.log_span(
        group_id="grp_sensitive",
        step_index=1,
        run_type="llm",
        name="model-test",
        start_time=100.0,
        end_time=101.0,
        status="success",
        inputs={"api_key": "secret-token-12345", "password": "super-secret-password"},
        outputs={"body": "token: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxfQ.abcdef"},
        metadata={"model": "test", "agent_mode": "react", "prompt_version": "v1"},
    )
    assert span["inputs"]["api_key"] == "[REDACTED_SECRET]"
    assert span["inputs"]["password"] == "[REDACTED_PASSWORD]"
