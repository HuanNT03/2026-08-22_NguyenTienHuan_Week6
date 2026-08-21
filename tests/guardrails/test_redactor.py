"""Unit and contract tests for the unified redactor engine (src/guardrails/redactor.py)."""

from typing import Any

from src.guardrails.redactor import mask_sensitive_data, sanitize_llm_messages


def test_redact_email() -> None:
    """Verify that various email formats are redacted properly."""
    text = "Contact admin@sentinel.internal or user.test+filter@sub.domain.co.uk for support."
    redacted = mask_sensitive_data(text)
    assert "admin@sentinel.internal" not in redacted
    assert "user.test+filter@sub.domain.co.uk" not in redacted
    assert "[REDACTED_EMAIL]" in redacted


def test_redact_vietnamese_and_intl_phone() -> None:
    """Verify that Vietnamese and international phone numbers are redacted."""
    text = "Call hotline 0912-345-678 or mobile +84988123456 or intl +1 555 123 4567."
    redacted = mask_sensitive_data(text)
    assert "0912-345-678" not in redacted
    assert "+84988123456" not in redacted
    assert "+1 555 123 4567" not in redacted
    assert "[REDACTED_PHONE]" in redacted


def test_redact_cccd_cmnd() -> None:
    """Verify that Vietnamese citizen identity card numbers (CCCD 12 digits) are redacted."""
    text = "Citizen CCCD: 001099012345 registered to user."
    redacted = mask_sensitive_data(text)
    assert "001099012345" not in redacted
    assert "[REDACTED_PII]" in redacted


def test_redact_credit_card() -> None:
    """Verify that credit card PAN numbers (13-19 digits with spaces/dashes) are redacted."""
    text = "Payment card Visa: 4532-0150-9988-1234 and Mastercard 5105105105105100."
    redacted = mask_sensitive_data(text)
    assert "4532-0150-9988-1234" not in redacted
    assert "5105105105105100" not in redacted
    assert "[REDACTED_CREDIT_CARD]" in redacted


def test_redact_jwt_and_bearer() -> None:
    """Verify that Bearer tokens and raw 3-part JWT strings are redacted."""
    raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    text = f"Headers: Authorization: Bearer {raw_jwt} and raw token={raw_jwt}"
    redacted = mask_sensitive_data(text)
    assert raw_jwt not in redacted
    assert "[REDACTED_JWT]" in redacted or "[REDACTED_SECRET]" in redacted


def test_redact_connection_strings() -> None:
    """Verify that DB connection string URIs have their passwords masked."""
    text = "Database connection: postgres://db_admin:SuperSecretPassword2026!@internal-db.node:5432/sentinel_db"
    redacted = mask_sensitive_data(text)
    assert "SuperSecretPassword2026!" not in redacted
    assert "postgres://db_admin:[REDACTED_PASSWORD]@internal-db.node:5432/sentinel_db" in redacted


def test_redact_inline_secrets() -> None:
    """Verify that inline password, api_key, and secret assignments are masked."""
    text = "Config values: password=P@ssw0rd123, mật khẩu là SecretPass999, api_key: sk-proj-1234567890abcdef12345678"
    redacted = mask_sensitive_data(text)
    assert "P@ssw0rd123" not in redacted
    assert "SecretPass999" not in redacted
    assert "sk-proj-1234567890abcdef12345678" not in redacted


def test_redact_nested_structures() -> None:
    """Verify that nested dictionaries, lists, and sensitive key names are handled recursively."""
    payload: dict[str, Any] = {
        "user_profile": {
            "email": "user@example.com",
            "phone": "0903888999",
            "tokens": ["sk_live_1234567890abcdef", "eyJhbGciOiJIUzI1NiIsIn..."],
        },
        "headers": {
            "authorization": "Bearer secret-token-value-123",
            "x-api-key": "sentinel-agent-key-999",
            "cookie": "session_id=abcdef123456",
            "content-type": "application/json",
        },
        "count": 42,
        "is_active": True,
    }
    redacted = mask_sensitive_data(payload)
    assert redacted["user_profile"]["email"] == "[REDACTED_EMAIL]"
    assert redacted["user_profile"]["phone"] == "[REDACTED_PHONE]"
    assert redacted["headers"]["authorization"] == "[REDACTED_SECRET]"
    assert redacted["headers"]["x-api-key"] == "[REDACTED_SECRET]"
    assert redacted["headers"]["cookie"] == "[REDACTED_SECRET]"
    assert redacted["headers"]["content-type"] == "application/json"
    assert redacted["count"] == 42
    assert redacted["is_active"] is True


def test_redact_primitives_and_edge_cases() -> None:
    """Verify primitive types and edge cases (None, numbers, booleans, empty strings)."""
    assert mask_sensitive_data(None) is None
    assert mask_sensitive_data(123) == 123
    assert mask_sensitive_data(45.67) == 45.67
    assert mask_sensitive_data(True) is True
    assert mask_sensitive_data("") == ""
    assert mask_sensitive_data("Clean safe text without secrets.") == "Clean safe text without secrets."


def test_sanitize_llm_messages() -> None:
    """Verify that OpenAI-format message lists are cleaned properly before LLM invocation."""
    messages = [
        {"role": "system", "content": "You are a security bot. API key: sk-secret-bot-key."},
        {"role": "user", "content": "Analyze user: admin@juice-sh.op with pass: SuperSecret123!"},
        {"role": "assistant", "content": "No secrets found here."},
    ]
    sanitized = sanitize_llm_messages(messages)
    assert "sk-secret-bot-key" not in sanitized[0]["content"]
    assert "admin@juice-sh.op" not in sanitized[1]["content"]
    assert "SuperSecret123!" not in sanitized[1]["content"]
    assert "[REDACTED_EMAIL]" in sanitized[1]["content"]
    assert sanitized[2]["content"] == "No secrets found here."
