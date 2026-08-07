"""Unit tests for src/agent/redaction.py."""

from src.agent.redaction import redact_sensitive_data


def test_redact_email() -> None:
    text = "User email is admin@example.com and dev.test+1@domain.co.uk"
    redacted = redact_sensitive_data(text)
    assert "admin@example.com" not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "dev.test+1@domain.co.uk" not in redacted


def test_redact_secret_tokens() -> None:
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and sk-1234567890abcdef1234567890"
    redacted = redact_sensitive_data(text)
    assert "Bearer eyJ" not in redacted
    assert "sk-1234567890" not in redacted
    assert "[REDACTED_SECRET]" in redacted


def test_redact_password() -> None:
    text = '{"username": "admin", "password": "supersecretpassword123"}'
    redacted = redact_sensitive_data(text)
    assert "supersecretpassword123" not in redacted
    assert "[REDACTED_PASSWORD]" in redacted


def test_redact_dict_recursively() -> None:
    data = {
        "user": "alice@company.com",
        "nested": {"token": "Bearer abcdef1234567890abcdef"},
    }
    redacted = redact_sensitive_data(data)
    assert redacted["user"] == "[REDACTED_EMAIL]"
    assert "[REDACTED_SECRET]" in redacted["nested"]["token"]
