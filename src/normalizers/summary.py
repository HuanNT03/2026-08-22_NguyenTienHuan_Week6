from typing import Any

from src.normalizers.common.models import ToolNormalizationResult


def successful_tool_summary(result: ToolNormalizationResult) -> dict[str, Any]:
    status = "partial" if any(result.warnings.values()) else "success"
    return {"status": status, **result.raw_counts, "warnings": result.warnings}


def failed_tool_summary(error: Exception) -> dict[str, Any]:
    return {
        "status": "failed",
        "findings_written": 0,
        "warnings": {},
        "error": str(error),
    }


def skipped_tool_summary() -> dict[str, Any]:
    return {
        "status": "skipped",
        "findings_written": 0,
        "warnings": {},
    }


def build_summary(
    *,
    schema_version: str,
    normalizer_version: str,
    normalized_at: str,
    tools: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "normalizer_version": normalizer_version,
        "normalized_at": normalized_at,
        "tools": tools,
        "total_findings_written": sum(
            int(tool.get("findings_written", 0))
            for tool in tools.values()
        ),
    }
