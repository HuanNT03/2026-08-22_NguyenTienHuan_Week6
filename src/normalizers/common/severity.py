from typing import Any

_ENUMS = {"info", "low", "medium", "high", "critical"}


def normalize_severity(tool_name: str, native_value: Any) -> str:
    if native_value is None or isinstance(native_value, bool):
        return "unknown"
    tool = tool_name.strip().lower()
    value = str(native_value).strip().lower().replace("-", "_")
    if tool == "semgrep":
        mapping = {
            "informational": "info", "info": "info", "low": "low",
            "warning": "medium", "medium": "medium", "error": "high",
            "high": "high", "critical": "critical",
        }
        return mapping.get(value, "unknown")
    if tool == "zap":
        return {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}.get(value, "unknown")
    if tool == "codeql":
        try:
            score = float(value)
        except (TypeError, ValueError):
            return "unknown"
        if score < 0 or score > 10:
            return "unknown"
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        if score > 0:
            return "low"
        return "info"
    return value if value in _ENUMS else "unknown"
