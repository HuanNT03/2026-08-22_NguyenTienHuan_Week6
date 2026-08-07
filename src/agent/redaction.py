"""Data redaction module for Project Sentinel Security Analysis Agent."""

import re
from typing import Any

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_PATTERN = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9._~+/-]+=*", re.IGNORECASE)
SECRET_KEY_PATTERN = re.compile(r"\b(?:sk|ghp|xoxb|xoxp|key)-[a-zA-Z0-9]{16,}\b", re.IGNORECASE)
PASSWORD_JSON_PATTERN = re.compile(r'("password"\s*:\s*")[^"]+(")', re.IGNORECASE)


def redact_text(text: str) -> str:
    """Redact email, phone, credentials, tokens from plain text string."""
    if not text:
        return text

    res = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
    res = PHONE_PATTERN.sub("[REDACTED_PHONE]", res)
    res = BEARER_PATTERN.sub("[REDACTED_SECRET]", res)
    res = SECRET_KEY_PATTERN.sub("[REDACTED_SECRET]", res)
    res = PASSWORD_JSON_PATTERN.sub(r"\1[REDACTED_PASSWORD]\2", res)
    return res


def redact_sensitive_data(val: Any) -> Any:
    """Recursively redact sensitive data from strings, dicts, and lists."""
    if isinstance(val, str):
        return redact_text(val)
    elif isinstance(val, dict):
        return {k: redact_sensitive_data(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [redact_sensitive_data(item) for item in val]
    return val
