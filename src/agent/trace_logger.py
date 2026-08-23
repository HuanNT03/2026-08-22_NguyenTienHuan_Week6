"""Project Sentinel - Agent Execution Trace Logger (LangSmith Compatible).

Module: src/agent/trace_logger.py
Mục đích:
    Ghi lại toàn bộ vết thực thi (Execution Spans), chu trình suy luận đa bước ReAct,
    các lệnh gọi LLM, lượt thực thi Tool, đối soát Guardrails và chốt chặn HITL
    vào file JSONL `logs/agent-runner.log` theo chuẩn schemas/agent_runner_log.schema.json.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from src.guardrails.redactor import mask_sensitive_data

logger = logging.getLogger(__name__)

DEFAULT_AGENT_LOG_FILE = Path(__file__).resolve().parents[2] / "logs" / "agent-runner.log"


def format_iso_utc(ts: float | datetime | str | None = None) -> str:
    """Chuyển đổi timestamp sang định dạng ISO-8601 UTC chuẩn."""
    if ts is None:
        return datetime.now(UTC).isoformat()
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=UTC).isoformat()
        return ts.astimezone(UTC).isoformat()
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=UTC).isoformat()
    return str(ts)


def normalize_group_id(raw_id: str) -> str:
    """Đảm bảo group_id bắt đầu bằng grp_ theo regex ^grp_[a-zA-Z0-9_:-]+$."""
    clean = str(raw_id).strip()
    if not clean.startswith("grp_"):
        clean = f"grp_{clean}"
    return clean


class TraceLogger:
    """Quản lý và ghi nhận trace spans cho Project Sentinel AI Agent."""

    def __init__(
        self,
        trace_id: str | None = None,
        log_file: Path | str | None = None,
    ) -> None:
        """Khởi tạo TraceLogger với trace_id duy nhất và đường dẫn tệp log.

        Args:
            trace_id: Mã định danh root trace (ví dụ: 'trc_...'). Nếu None, tự sinh UUID 32 ký tự hex.
            log_file: Đường dẫn tệp log JSONL đích (mặc định: logs/agent-runner.log).
        """
        self.trace_id = trace_id or f"trc_{uuid.uuid4().hex}"
        self.log_file = Path(log_file) if log_file else DEFAULT_AGENT_LOG_FILE
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def generate_run_id(self) -> str:
        """Sinh mã span run_id duy nhất tuân thủ định dạng ^run_[0-9a-f]{32}$."""
        return f"run_{uuid.uuid4().hex}"

    def log_span(
        self,
        group_id: str,
        step_index: int,
        run_type: Literal["chain", "llm", "tool", "retriever", "guardrail", "hitl"],
        name: str,
        start_time: float | datetime | str,
        end_time: float | datetime | str,
        status: Literal["running", "success", "error", "rejected", "timed_out"],
        inputs: dict[str, Any],
        outputs: Any,
        metadata: dict[str, Any],
        run_id: str | None = None,
        parent_run_id: str | None = None,
        token_usage: dict[str, int] | None = None,
        error: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Ghi nhận một execution span JSONL vào file log theo schema agent_runner_log.

        Args:
            group_id: Mã định danh nhóm AnalysisGroup.
            step_index: Thứ tự bước (0-indexed).
            run_type: Phân loại span ('chain', 'llm', 'tool', 'retriever', 'guardrail', 'hitl').
            name: Tên của hành động/bước thực thi.
            start_time: Thời điểm bắt đầu (timestamp/datetime/ISO str).
            end_time: Thời điểm kết thúc (timestamp/datetime/ISO str).
            status: Trạng thái kết quả ('running', 'success', 'error', 'rejected', 'timed_out').
            inputs: Dữ liệu đầu vào (được tự động khử khuẩn sensitive data).
            outputs: Dữ liệu đầu ra (thought, tool calls, observation...).
            metadata: Metadata ngữ cảnh (model, agent_mode, prompt_version,...).
            run_id: Tùy chọn span ID cụ thể.
            parent_run_id: Tùy chọn parent span ID.
            token_usage: Thống kê token (prompt_tokens, completion_tokens, total_tokens).
            error: Thông tin lỗi cấu trúc (error_type, message, stack_trace).

        Returns:
            dict[str, Any]: Đối tượng span hoàn chỉnh đã ghi vào file.
        """
        start_iso = format_iso_utc(start_time)
        end_iso = format_iso_utc(end_time)

        # Tính toán duration_ms
        if isinstance(start_time, (int, float)) and isinstance(end_time, (int, float)):
            duration_ms = max(0.0, round((end_time - start_time) * 1000.0, 2))
        else:
            duration_ms = 0.0

        # Làm sạch inputs và outputs tránh rò rỉ bí mật
        sanitized_inputs = mask_sensitive_data(inputs)
        sanitized_outputs = mask_sensitive_data(outputs) if isinstance(outputs, (dict, list)) else outputs

        # Chuẩn hóa metadata bắt buộc
        meta_dict: dict[str, Any] = {
            "model": metadata.get("model", "unknown-model"),
            "agent_mode": metadata.get("agent_mode", "react"),
            "prompt_version": metadata.get("prompt_version", "system_v2"),
        }
        for opt_key in (
            "temperature",
            "max_steps",
            "tool_name",
            "target_endpoint",
            "fingerprints",
            "prompt_injection_detected",
            "tags",
        ):
            if opt_key in metadata and metadata[opt_key] is not None:
                meta_dict[opt_key] = metadata[opt_key]

        span_record: dict[str, Any] = {
            "schema_version": "1.0.0",
            "trace_id": self.trace_id,
            "run_id": run_id or self.generate_run_id(),
            "parent_run_id": parent_run_id,
            "group_id": normalize_group_id(group_id),
            "step_index": max(0, int(step_index)),
            "run_type": run_type,
            "name": str(name).strip() or "UnnamedSpan",
            "start_time": start_iso,
            "end_time": end_iso,
            "duration_ms": duration_ms,
            "status": status,
            "inputs": sanitized_inputs if isinstance(sanitized_inputs, dict) else {"raw": sanitized_inputs},
            "outputs": sanitized_outputs,
            "token_usage": token_usage,
            "error": error,
            "metadata": meta_dict,
        }

        try:
            line = json.dumps(span_record, ensure_ascii=False)
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as err:  # noqa: BLE001
            logger.warning("Failed to write trace span to %s: %s", self.log_file, err)

        return span_record
