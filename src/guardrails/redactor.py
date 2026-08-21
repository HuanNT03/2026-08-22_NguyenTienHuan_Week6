"""Unified Redactor Engine for Project Sentinel.

This module provides centralized data sanitization and masking for PII, secrets,
credentials, tokens, connection strings, and financial identifiers across all system components.
"""

import re
from typing import Any

# 1. Bearer tokens & JWTs
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.=]+", re.IGNORECASE)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")

# 2. Database Connection Strings (postgres, mysql, mongodb, redis, etc.)
CONNECTION_STRING_PATTERN = re.compile(
    r"\b((?:postgres|postgresql|mysql|mongodb|redis)://[^:\s@]+):([^@\s]+)(@[^\s]+)\b",
    re.IGNORECASE,
)

# 3. Inline Secrets, Passwords, API Keys (English & Vietnamese keywords)
INLINE_PASSWORD_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|pass|mật\s*khẩu)\s*(?:[:=]|is|\blà\b)\s*[\"']?([^\s\"',;}{]+)[\"']?",
    re.IGNORECASE,
)
INLINE_SECRET_PATTERN = re.compile(
    r"(?i)\b(secret(?:_key)?|api[_\s]?key|access[_\s]?token|auth[_\s]?token)\s*(?:[:=]|is|\blà\b)\s*[\"']?([^\s\"',;}{]+)[\"']?",
    re.IGNORECASE,
)
GENERIC_SECRET_KEY_PATTERN = re.compile(r"\b(?:sk|pk)_(?:live|test|proj)_[0-9a-zA-Z]{16,}\b|\bsk-[a-zA-Z0-9_\-]{8,}\b")

# 4. Credit Card / PAN (13-19 digits with optional hyphens or spaces)
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{1,4}|5[1-5][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}|3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5})\b"
)

# 5. Vietnamese Citizen Identity Card (CCCD 12 digits or CMND 9 digits)
CCCD_PATTERN = re.compile(r"\b0[0-9]{2}[0-3][0-9]{2}[0-9]{6}\b|\b0[0-9]{11}\b")

# 6. Phone Numbers (Vietnamese prefixes 03x, 05x, 07x, 08x, 09x, +84, and international)
VIETNAMESE_PHONE_PATTERN = re.compile(
    r"(?:\+84|84|0)(?:3[2-9]|5[25689]|7[06-9]|8[1-9]|9[0-9])(?:[-. ]?[0-9]{1,4}){2,3}\b"
)
INTL_PHONE_PATTERN = re.compile(r"(?:^|[\s,;:(])\+([0-9][- ]?){6,14}[0-9]\b")

# 7. Email Addresses
EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")

# Sensitive Dictionary Keys (Case-insensitive)
SENSITIVE_KEYS = {
    "authorization",
    "x-api-key",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "secret_key",
    "access_token",
}


def _mask_string(text: str) -> str:
    """Apply multi-layer regex rules to mask sensitive patterns in a plain text string.

    Args:
        text: Freeform text string potentially containing PII or secrets.

    Returns:
        Sanitized string with sensitive substrings replaced with standard tags.
    """
    if not text or not isinstance(text, str):
        return text

    res = text

    # 1. Bearer tokens & JWTs
    res = BEARER_PATTERN.sub("Bearer [REDACTED_SECRET]", res)
    res = JWT_PATTERN.sub("[REDACTED_JWT]", res)

    # 2. Connection strings
    res = CONNECTION_STRING_PATTERN.sub(r"\1:[REDACTED_PASSWORD]\3", res)

    # 3. Inline passwords & secrets
    res = INLINE_PASSWORD_PATTERN.sub(r"\1=[REDACTED_PASSWORD]", res)
    res = INLINE_SECRET_PATTERN.sub(r"\1=[REDACTED_SECRET]", res)
    res = GENERIC_SECRET_KEY_PATTERN.sub("[REDACTED_SECRET]", res)

    # 4. Credit card PAN
    res = CREDIT_CARD_PATTERN.sub("[REDACTED_CREDIT_CARD]", res)

    # 5. CCCD / CMND
    res = CCCD_PATTERN.sub("[REDACTED_PII]", res)

    # 6. Phone numbers
    res = VIETNAMESE_PHONE_PATTERN.sub("[REDACTED_PHONE]", res)
    res = INTL_PHONE_PATTERN.sub(lambda m: m.group(0)[0] + "[REDACTED_PHONE]" if m.group(0)[0] in " \t\n,;:( " else "[REDACTED_PHONE]", res)

    # 7. Emails
    res = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", res)

    return res


def mask_sensitive_data(data: Any) -> Any:
    """Recursively mask sensitive PII and secrets in any data structure.

    This function acts as the single unified entry point for redaction across
    the entire Project Sentinel codebase. It handles strings, dictionaries,
    lists, tuples, sets, and primitive types recursively.

    Args:
        data: Any Python data structure (dict, list, str, tuple, set, primitive).

    Returns:
        A deep copy of the data structure with all sensitive substrings and
        sensitive dictionary header keys masked.
    """
    if data is None or isinstance(data, (int, float, bool)):
        return data

    if isinstance(data, str):
        return _mask_string(data)

    if isinstance(data, dict):
        sanitized_dict: dict[str, Any] = {}
        for k, v in data.items():
            key_lower = str(k).lower().replace("_", "").replace("-", "")
            # Check if key is sensitive header or credential field
            if any(key_lower == s.replace("_", "").replace("-", "") for s in SENSITIVE_KEYS):
                if isinstance(v, str) and not v.startswith("[REDACTED_"):
                    if "password" in key_lower or "passwd" in key_lower or "pwd" in key_lower:
                        sanitized_dict[k] = "[REDACTED_PASSWORD]"
                    else:
                        sanitized_dict[k] = "[REDACTED_SECRET]"
                else:
                    sanitized_dict[k] = mask_sensitive_data(v)
            else:
                sanitized_dict[k] = mask_sensitive_data(v)
        return sanitized_dict

    if isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]

    if isinstance(data, tuple):
        return tuple(mask_sensitive_data(item) for item in data)

    if isinstance(data, set):
        return {mask_sensitive_data(item) for item in data}

    return data


def sanitize_llm_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sanitize all messages in OpenAI chat completion format before LLM invocation.

    Ensures that no system prompts, user queries, assistant messages, or tool outputs
    leak unredacted credentials to cloud LLM providers.

    Args:
        messages: List of OpenAI-format chat message dictionaries.

    Returns:
        List of sanitized message dictionaries with contents masked.
    """
    sanitized: list[dict[str, Any]] = []
    for msg in messages:
        msg_copy = dict(msg)
        if "content" in msg_copy and msg_copy["content"] is not None:
            msg_copy["content"] = mask_sensitive_data(msg_copy["content"])
        sanitized.append(msg_copy)
    return sanitized
