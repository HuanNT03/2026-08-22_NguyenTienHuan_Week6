"""Data redaction module for Project Sentinel Security Analysis Agent.

DEPRECATION NOTE:
This module is maintained for backward compatibility. All core redaction
logic is consolidated into `src.guardrails.redactor.mask_sensitive_data`.
"""

from typing import Any

from src.guardrails.redactor import mask_sensitive_data


def redact_text(text: str) -> str:
    """Legacy wrapper for redacting plain text strings."""
    return mask_sensitive_data(text)


def redact_sensitive_data(val: Any) -> Any:
    """Legacy wrapper for recursively redacting sensitive data structures."""
    return mask_sensitive_data(val)
