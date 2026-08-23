"""Project Sentinel - Gateway Network Audit Logger.

Module: src/gateway/logger.py
Mục đích:
    Ghi vết toàn diện và an toàn mọi giao dịch mạng (HTTP Request & Response) qua API Gateway.
    - Đảm bảo tuân thủ nghiêm ngặt data contract `schemas/gateway_audit.schema.json`.
    - Tự động khử khuẩn bí mật (x-api-key, Bearer token, password) và PII trước khi ghi xuống đĩa.
    - Tự động phát hiện cờ Prompt Injection và phân loại rủi ro Inbound.
    - Tuyệt đối không để lộ secret hoặc PII trong tệp nhật ký persistent trên đĩa.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.guardrails.injection import detect_prompt_injection
from src.guardrails.redactor import mask_sensitive_data

DEFAULT_LOG_FILE = Path("logs/gateway-network-audit.jsonl")

VALID_APPROVAL_STATUSES = {
    "APPROVED",
    "AUTO_APPROVED",
    "REJECTED_BY_USER",
    "REJECTED_BY_TIMEOUT",
    "NOT_REQUIRED",
}


def build_audit_record(
    endpoint: str,
    method: str,
    status_code: int = 0,
    duration_ms: float = 0.0,
    approval_status: str = "NOT_REQUIRED",
    request_headers: dict[str, Any] | None = None,
    response_headers: dict[str, Any] | None = None,
    response_body_snippet: str = "",
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Construct a sanitized, validated audit record dictionary adhering to gateway_audit.schema.json.

    Args:
        endpoint: Target HTTP path requested (e.g. '/api/Products').
        method: HTTP method (e.g. 'GET', 'POST', 'OPTIONS').
        status_code: Integer HTTP status code (0 if rejected/unreachable).
        duration_ms: Total roundtrip execution latency in milliseconds.
        approval_status: HITL approval state (APPROVED, AUTO_APPROVED, REJECTED_BY_USER,
            REJECTED_BY_TIMEOUT, NOT_REQUIRED).
        request_headers: Raw or partial outbound request headers.
        response_headers: Raw inbound response headers.
        response_body_snippet: Preview string of response body (bounded <= 2KB).
        timestamp: Optional ISO-8601 timestamp string. If None, current UTC time is used.

    Returns:
        A dictionary containing all required fields guaranteed to match the audit JSON Schema,
        with all credentials and PII completely redacted.
    """
    ts = timestamp or datetime.now(UTC).isoformat()
    clean_method = method.strip().upper() if isinstance(method, str) else "UNKNOWN"
    clean_endpoint = endpoint.strip() if isinstance(endpoint, str) else "/"
    clean_status = int(status_code) if isinstance(status_code, (int, float)) else 0

    norm_approval = approval_status.strip().upper() if isinstance(approval_status, str) else "NOT_REQUIRED"
    if norm_approval not in VALID_APPROVAL_STATUSES:
        norm_approval = "NOT_REQUIRED"

    # Redact request headers
    raw_req_headers = dict(request_headers) if request_headers else {}
    masked_req_headers = mask_sensitive_data(raw_req_headers)
    if not isinstance(masked_req_headers, dict):
        masked_req_headers = {}

    # Redact response headers
    raw_resp_headers = dict(response_headers) if response_headers else {}
    masked_resp_headers = mask_sensitive_data(raw_resp_headers)
    if not isinstance(masked_resp_headers, dict):
        masked_resp_headers = {}

    # Redact response body preview
    clean_body = str(response_body_snippet or "")
    masked_body = mask_sensitive_data(clean_body)
    if not isinstance(masked_body, str):
        masked_body = str(masked_body)

    # Detect prompt injection in response body
    is_injection, _ = detect_prompt_injection(clean_body)
    injection_detected = bool(is_injection)
    injection_risk = "SUSPICIOUS_INJECTION_DETECTED" if injection_detected else "NONE"

    # Calculate redaction metrics
    redacted_types_set: set[str] = set()
    body_redaction_markers = [
        ("[REDACTED_EMAIL]", "EMAIL"),
        ("[REDACTED_PASSWORD]", "PASSWORD"),
        ("[REDACTED_SECRET]", "SECRET_TOKEN"),
        ("[REDACTED_PHONE]", "PHONE"),
        ("[REDACTED_NATIONAL_ID]", "NATIONAL_ID"),
        ("[REDACTED_CREDIT_CARD]", "CREDIT_CARD"),
        ("[REDACTED_DB_URI]", "DATABASE_URI"),
    ]
    redaction_count = 0
    for marker, label in body_redaction_markers:
        count = masked_body.count(marker)
        if count > 0:
            redaction_count += count
            redacted_types_set.add(label)

    # Also check if request headers had redaction applied
    req_headers_str = json.dumps(masked_req_headers)
    for marker, label in body_redaction_markers:
        count = req_headers_str.count(marker)
        if count > 0:
            redaction_count += count
            redacted_types_set.add(label)

    redaction_applied = redaction_count > 0 or ("[REDACTED" in masked_body) or ("[REDACTED" in req_headers_str)

    return {
        "timestamp": ts,
        "endpoint": clean_endpoint,
        "method": clean_method,
        "status_code": clean_status,
        "duration_ms": round(float(duration_ms), 2),
        "approval_status": norm_approval,
        "guardrails": {
            "redaction_applied": redaction_applied,
            "redacted_types": sorted(redacted_types_set),
            "redaction_count": redaction_count,
            "prompt_injection_detected": injection_detected,
            "prompt_injection_risk": injection_risk,
        },
        "request_headers": masked_req_headers,
        "response_headers": masked_resp_headers,
        "response_body_snippet": masked_body,
    }


def log_audit_event(
    endpoint: str,
    method: str,
    status_code: int = 0,
    duration_ms: float = 0.0,
    approval_status: str = "NOT_REQUIRED",
    request_headers: dict[str, Any] | None = None,
    response_headers: dict[str, Any] | None = None,
    response_body_snippet: str = "",
    log_file: Path | str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Record a sanitized HTTP network audit event to the persistent JSONL audit log file.

    Args:
        endpoint: Target HTTP path requested (e.g. '/api/Products').
        method: HTTP method (e.g. 'GET', 'POST', 'OPTIONS').
        status_code: Integer HTTP status code (0 if connection error or rejected before sending).
        duration_ms: Total latency in milliseconds.
        approval_status: HITL decision (APPROVED, AUTO_APPROVED, REJECTED_BY_USER,
            REJECTED_BY_TIMEOUT, NOT_REQUIRED).
        request_headers: Outbound request headers.
        response_headers: Inbound response headers.
        response_body_snippet: Snippet of response body.
        log_file: Optional custom destination file path. Defaults to logs/gateway-network-audit.jsonl.
        timestamp: Optional ISO-8601 timestamp string.

    Returns:
        dict[str, Any]: The exact serialized audit record dictionary that was appended to the log file.

    Side Effects:
        Appends a single JSON line to the target log file. Creates parent directories if missing.
    """
    record = build_audit_record(
        endpoint=endpoint,
        method=method,
        status_code=status_code,
        duration_ms=duration_ms,
        approval_status=approval_status,
        request_headers=request_headers,
        response_headers=response_headers,
        response_body_snippet=response_body_snippet,
        timestamp=timestamp,
    )

    target_path = Path(log_file) if log_file else DEFAULT_LOG_FILE
    target_path.parent.mkdir(parents=True, exist_ok=True)

    with open(target_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record
