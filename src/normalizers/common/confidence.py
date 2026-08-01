from typing import Any


def normalize_confidence(tool_name: str, native_value: Any) -> str:
    if native_value is None or isinstance(native_value, bool):
        return "unknown"
    tool = tool_name.strip().lower()
    value = str(native_value).strip().lower().replace("-", "_").replace(" ", "_")
    common = {
        "false_positive": "false_positive", "low": "low", "medium": "medium",
        "high": "high", "confirmed": "confirmed",
    }
    if tool == "zap":
        return {"0": "false_positive", "1": "low", "2": "medium", "3": "high", "4": "confirmed"}.get(value, "unknown")
    if tool == "codeql":
        if value in {"very_low", "low"}:
            return "low"
        if value == "medium":
            return "medium"
        if value in {"high", "very_high"}:
            return "high"
        return "unknown"
    if tool == "semgrep":
        return common.get(value, "unknown")
    return common.get(value, "unknown")
