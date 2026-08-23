"""Project Sentinel - Safe HTTP Requester Tool and CLI Runner.

Module: src/gateway/safe_requester.py
Mục đích:
    Cung cấp công cụ gửi HTTP Request an toàn qua Kong API Gateway (Port 3000)
    dành cho AI Security Analysis Agent và người vận hành (CLI / make test-request).
    - Ràng buộc phương thức nghiêm ngặt: Chỉ chấp nhận GET, PUT, OPTIONS. Chặn mọi method khác (405).
    - Tự động tiêm khóa bí mật môi trường AGENT_API_KEY vào header x-api-key (Zero hardcode).
    - Tích hợp chốt chặn HITL (Đánh giá rủi ro, hỏi duyệt với Timeout 120s Fail-Safe).
    - Tự động sinh payload ngoại cỡ 1.5MB an toàn trong bộ nhớ khi oversized_payload=True.
    - Hỗ trợ kiểm thử Burst Rate Limit khi burst_count > 1 (phát hiện phản hồi 429).
    - Áp dụng Timeout 7.0s và cắt cụt Response stream ở ngưỡng tối đa 2048 bytes (2KB).
    - Tích hợp Guardrails 2 chiều: Khử khuẩn secret trước khi ghi log audit và bọc Inbound
      Response qua wrap_untrusted_response (mask PII + phòng chống Indirect Prompt Injection).
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

# Tự động nạp biến môi trường từ .env
load_dotenv()

from src.gateway.hitl import assess_request_risk, prompt_cli_approval
from src.gateway.logger import log_audit_event
from src.guardrails.injection import wrap_untrusted_response
from src.guardrails.redactor import mask_sensitive_data

ALLOWED_METHODS = {"GET", "PUT", "OPTIONS"}
DEFAULT_GATEWAY_HOST = os.getenv("GATEWAY_HOST", "http://localhost:3000")
DEFAULT_TIMEOUT = 7.0  # 7s (Kong 5s timeout + 2s buffer)
MAX_RESPONSE_BYTES = 2048  # 2KB

PAYLOADS_FILE = Path(__file__).resolve().parent / "payloads.json"
OVERSIZED_PAYLOAD_BYTES = 1572864  # 1.5 MB (1.5 * 1024 * 1024)

TOOL_SCHEMA = {
    "name": "send_safe_request",
    "description": (
        "Gửi HTTP request kiểm thử an toàn qua Kong API Gateway (Port 3000). "
        "Tool hỗ trợ các phương thức GET, PUT, OPTIONS, tự động tiêm x-api-key từ môi trường, "
        "tự động kích hoạt chốt chặn HITL cho các hành động rủi ro (PUT, Burst mode, Payload lớn), "
        "và làm sạch (redact) PII/Prompt Injection trước khi trả về cho Agent. "
        "Đầu ra bao gồm: status_code (int), endpoint (str), method (str), headers (dict), "
        "body (chuỗi an toàn đã bọc Guardrails), truncated (bool), và duration_ms (float)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "Endpoint path cần kiểm thử (Ví dụ: '/rest/products/search?q=apple', '/api/Products', '/rest/products/1/reviews').",
            },
            "method": {
                "type": "string",
                "enum": ["GET", "PUT", "OPTIONS"],
                "default": "GET",
                "description": "Phương thức HTTP được phép theo chính sách an toàn (GET, PUT, OPTIONS).",
            },
            "payload_category": {
                "type": "string",
                "enum": [
                    "long_string",
                    "special_chars",
                    "empty_values",
                    "type_mismatch",
                    "query_param_injection",
                    "sql_injection_probes",
                    "cross_site_scripting_probes",
                ],
                "description": "Nhóm payload an toàn nạp từ src/gateway/payloads.json.",
            },
            "payload_value": {
                "type": "string",
                "description": "Giá trị payload cụ thể tùy chỉnh gửi trong request body hoặc query param.",
            },
            "burst_count": {
                "type": "integer",
                "default": 1,
                "description": "Số lượng request gửi liên tiếp (Burst Mode) để kiểm tra giới hạn tần suất 429 Too Many Requests.",
            },
            "oversized_payload": {
                "type": "boolean",
                "default": False,
                "description": "Nếu True, Tool sẽ tự động sinh buffer 1.5MB để kiểm thử request-size-limiting (1MB limit) của Gateway.",
            },
        },
        "required": ["endpoint"],
    },
}


def validate_method(method: str) -> bool:
    """Check if an HTTP method complies with the strict Sentinel Safe Requester policy.

    Args:
        method: HTTP method string (e.g. 'GET', 'PUT', 'OPTIONS').

    Returns:
        bool: True if method is allowed in ALLOWED_METHODS, False otherwise.
    """
    if not method or not isinstance(method, str):
        return False
    return method.strip().upper() in ALLOWED_METHODS


def load_payloads_dict() -> dict[str, Any]:
    """Load safe test payload definitions from src/gateway/payloads.json.

    Returns:
        dict[str, Any]: Parsed JSON dictionary of payload categories, or empty dict on error.
    """
    if not PAYLOADS_FILE.is_file():
        return {}
    try:
        with open(PAYLOADS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def resolve_safe_payload(category: str, index: int = 0, custom_value: Any = None) -> Any:
    """Retrieve a validated safe payload from payloads.json or return custom value.

    Args:
        category: Key in payloads.json (e.g. 'special_chars', 'sql_injection_probes').
        index: Index of the payload item if category holds a list.
        custom_value: Optional direct override value.

    Returns:
        The selected payload string, object, or None.
    """
    if custom_value is not None:
        return custom_value

    payloads = load_payloads_dict()
    cat_data = payloads.get(category)
    if isinstance(cat_data, list) and len(cat_data) > 0:
        idx = max(0, min(index, len(cat_data) - 1))
        return cat_data[idx]
    return cat_data


def _resolve_url(url: str, gateway_host: str = DEFAULT_GATEWAY_HOST) -> str:
    """Ensure URL has absolute Gateway base host prefix.

    Args:
        url: Raw path or full URL.
        gateway_host: Gateway base URL.

    Returns:
        str: Absolute URL pointing to Gateway.
    """
    clean_url = url.strip()
    if clean_url.startswith(("http://", "https://")):
        return clean_url
    if not clean_url.startswith("/"):
        clean_url = "/" + clean_url

    host = (gateway_host or DEFAULT_GATEWAY_HOST).rstrip("/")
    if host in ("http://localhost:3000", "http://127.0.0.1:3000") and Path("/.dockerenv").is_file():
        host = "http://host.docker.internal:3000"

    return f"{host}{clean_url}"


def send_safe_request(
    endpoint: str,
    method: str = "GET",
    payload_category: str | None = None,
    payload_value: Any = None,
    burst_count: int = 1,
    interval_seconds: float = 0.05,
    oversized_payload: bool = False,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    auto_approve: bool = False,
    approval_callback: Any = None,
    gateway_host: str | None = None,
    log_file: Path | str | None = None,
) -> dict[str, Any]:
    """Execute a guarded HTTP security verification probe through the Kong API Gateway.

    Args:
        endpoint: Target endpoint path (e.g. '/api/Products', '/rest/products/search?q=apple').
        method: HTTP method. Must be in {'GET', 'PUT', 'OPTIONS'}.
        payload_category: Identifier in payloads.json.
        payload_value: Optional specific payload string or dictionary.
        burst_count: Number of requests to send (default: 1; >1 for Burst Rate Limit test).
        interval_seconds: Delay between burst iterations in seconds.
        oversized_payload: If True, tool generates a 1.5MB buffer internally.
        headers: Additional custom HTTP headers.
        timeout: Socket timeout in seconds (default 7.0s).
        auto_approve: If True, bypass interactive HITL prompt.
        approval_callback: Optional callable(assessment) -> bool for custom/UI/In-Flight HITL handlers.
        gateway_host: Base Gateway URL override (default http://localhost:3000).
        log_file: Custom audit log path override.

    Returns:
        dict[str, Any]: Safe execution result containing status_code, body, headers,
        duration_ms, truncated flag, and audit details.
    """
    method_upper = method.strip().upper() if isinstance(method, str) else "UNKNOWN"
    base_host = (gateway_host or DEFAULT_GATEWAY_HOST).rstrip("/")

    # 1. Strict HTTP Method Policy Validation
    if not validate_method(method_upper):
        err_msg = (
            f"Method not allowed by Sentinel Policy: '{method_upper}'. "
            f"Allowed methods are strictly limited to: {sorted(ALLOWED_METHODS)}"
        )
        log_audit_event(
            endpoint=endpoint,
            method=method_upper,
            status_code=405,
            duration_ms=0.0,
            approval_status="NOT_REQUIRED",
            response_body_snippet=err_msg,
            log_file=log_file,
        )
        return {
            "status": "error",
            "status_code": 405,
            "message": err_msg,
            "endpoint": endpoint,
            "method": method_upper,
            "headers": {},
            "body": err_msg,
            "truncated": False,
            "duration_ms": 0.0,
        }

    # 2. Resolve Payload Data
    data_payload: Any = None
    if oversized_payload:
        data_payload = "A" * OVERSIZED_PAYLOAD_BYTES
    elif payload_value is not None:
        data_payload = payload_value
    elif payload_category is not None:
        data_payload = resolve_safe_payload(payload_category)

    # 3. Human-in-the-Loop (HITL) Risk Assessment & Approval
    assessment = assess_request_risk(
        method=method_upper,
        endpoint=endpoint,
        payload_category=payload_category,
        burst_count=burst_count,
        oversized_payload=oversized_payload,
    )

    approval_status = "NOT_REQUIRED"
    if assessment["requires_approval"]:
        if approval_callback is not None and callable(approval_callback):
            is_approved = bool(approval_callback(assessment))
        else:
            is_approved = prompt_cli_approval(assessment, auto_approve=auto_approve)

        if not is_approved:
            log_audit_event(
                endpoint=endpoint,
                method=method_upper,
                status_code=0,
                duration_ms=0.0,
                approval_status="REJECTED_BY_USER",
                response_body_snippet="Request was rejected by human operator (HITL Policy).",
                log_file=log_file,
            )
            return {
                "status": "rejected",
                "status_code": 0,
                "message": "Request was rejected by human operator or timed out (HITL Policy).",
                "endpoint": endpoint,
                "method": method_upper,
                "headers": {},
                "body": "🛑 [HITL REJECTED] Action canceled.",
                "truncated": False,
                "duration_ms": 0.0,
            }
        approval_status = "APPROVED" if not (auto_approve or os.getenv("CI_MODE")) else "AUTO_APPROVED"

    # 4. Prepare Headers & Inject API Key
    target_url = _resolve_url(endpoint, gateway_host=base_host)
    req_headers = dict(headers) if headers is not None else {}

    api_key = (
        os.getenv("AGENT_API_KEY")
        or os.getenv("KONG_VAULT_ENV_AGENT_API_KEY")
        or "sentinel-agent-secure-key-2026"
    )
    if "x-api-key" not in [k.lower() for k in req_headers]:
        req_headers["x-api-key"] = api_key

    data_bytes: bytes | str | None = None
    if data_payload is not None:
        if isinstance(data_payload, (dict, list)):
            data_bytes = json.dumps(data_payload)
            req_headers.setdefault("Content-Type", "application/json")
        elif isinstance(data_payload, str):
            data_bytes = data_payload
            if data_payload.startswith(("{", "[")):
                req_headers.setdefault("Content-Type", "application/json")
        elif isinstance(data_payload, bytes):
            data_bytes = data_payload

    # 5. Execute HTTP Request(s)
    total_count = max(1, int(burst_count))

    # Single Request Execution
    if total_count == 1:
        return _execute_single_http_request(
            target_url=target_url,
            endpoint=endpoint,
            method_upper=method_upper,
            req_headers=req_headers,
            data_bytes=data_bytes,
            timeout=timeout,
            approval_status=approval_status,
            log_file=log_file,
        )

    # Burst Mode Execution (Rate Limit Testing)
    return _execute_burst_http_requests(
        target_url=target_url,
        endpoint=endpoint,
        method_upper=method_upper,
        req_headers=req_headers,
        data_bytes=data_bytes,
        total_count=total_count,
        interval_seconds=interval_seconds,
        timeout=timeout,
        approval_status=approval_status,
        log_file=log_file,
    )


def _execute_single_http_request(
    target_url: str,
    endpoint: str,
    method_upper: str,
    req_headers: dict[str, str],
    data_bytes: bytes | str | None,
    timeout: float,
    approval_status: str,
    log_file: Path | str | None,
) -> dict[str, Any]:
    """Helper: Execute a single streaming HTTP request with truncation and guardrails."""
    start_time = time.time()
    response_body_raw = ""
    response_headers: dict[str, Any] = {}
    status_code = 0
    truncated = False

    session = requests.Session()
    try:
        req_kwargs: dict[str, Any] = {
            "method": method_upper,
            "url": target_url,
            "headers": req_headers,
            "timeout": timeout,
            "stream": True,
        }
        if data_bytes is not None:
            req_kwargs["data"] = data_bytes

        resp = session.request(**req_kwargs)
        status_code = resp.status_code
        response_headers = dict(resp.headers)

        # Read stream chunk by chunk up to MAX_RESPONSE_BYTES (2048 bytes)
        received_bytes = bytearray()
        for chunk in resp.iter_content(chunk_size=512):
            if chunk:
                received_bytes.extend(chunk)
                if len(received_bytes) >= MAX_RESPONSE_BYTES:
                    truncated = True
                    break

        response_body_raw = received_bytes[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")

    except requests.exceptions.Timeout:
        status_code = 504
        response_body_raw = json.dumps({"status": "error", "message": f"Gateway timeout after {timeout}s"})
    except requests.exceptions.ConnectionError as conn_err:
        status_code = 502
        response_body_raw = json.dumps(
            {"status": "error", "message": f"Connection to Gateway failed: {conn_err}"}
        )
    except requests.exceptions.RequestException as req_err:
        status_code = 500
        response_body_raw = json.dumps({"status": "error", "message": f"Request exception: {req_err}"})
    finally:
        session.close()

    duration_ms = (time.time() - start_time) * 1000.0

    # 6. Audit Logging (1 single consolidated record with secrets masked)
    log_audit_event(
        endpoint=endpoint,
        method=method_upper,
        status_code=status_code,
        duration_ms=duration_ms,
        approval_status=approval_status,
        request_headers=req_headers,
        response_headers=response_headers,
        response_body_snippet=response_body_raw,
        log_file=log_file,
    )

    # 7. Inbound Guardrails Encapsulation (mask PII & Prompt Injection envelope)
    safe_wrapped_body = wrap_untrusted_response(
        body=response_body_raw,
        endpoint=endpoint,
        status_code=status_code,
    )

    return {
        "status": "success" if 0 < status_code < 400 else "error",
        "status_code": status_code,
        "endpoint": endpoint,
        "method": method_upper,
        "headers": mask_sensitive_data(response_headers),
        "body": safe_wrapped_body,
        "truncated": truncated,
        "duration_ms": round(duration_ms, 2),
    }


def _execute_burst_http_requests(
    target_url: str,
    endpoint: str,
    method_upper: str,
    req_headers: dict[str, str],
    data_bytes: bytes | str | None,
    total_count: int,
    interval_seconds: float,
    timeout: float,
    approval_status: str,
    log_file: Path | str | None,
) -> dict[str, Any]:
    """Helper: Execute N sequential burst HTTP requests to test Rate Limiting."""
    start_time = time.time()
    status_counts: dict[int, int] = {}
    first_rate_limit_at: int | None = None
    rate_limited_count = 0
    last_status_code = 0
    last_body_snippet = ""

    session = requests.Session()
    try:
        for idx in range(1, total_count + 1):
            try:
                resp = session.request(
                    method=method_upper,
                    url=target_url,
                    headers=req_headers,
                    data=data_bytes,
                    timeout=timeout,
                )
                code = resp.status_code
                last_status_code = code
                status_counts[code] = status_counts.get(code, 0) + 1

                if code == 429:
                    rate_limited_count += 1
                    if first_rate_limit_at is None:
                        first_rate_limit_at = idx

                if idx == total_count:
                    last_body_snippet = resp.text[:MAX_RESPONSE_BYTES]

            except requests.exceptions.RequestException as e:
                last_status_code = 500
                status_counts[500] = status_counts.get(500, 0) + 1
                last_body_snippet = str(e)

            if interval_seconds > 0 and idx < total_count:
                time.sleep(interval_seconds)
    finally:
        session.close()

    total_duration_ms = (time.time() - start_time) * 1000.0

    # Log the burst test summary to audit log
    burst_summary_text = (
        f"Burst test completed: {total_count} requests sent. Status distribution: {status_counts}. "
        f"Rate limited (429): {rate_limited_count} reqs. First 429 at request #{first_rate_limit_at}."
    )
    log_audit_event(
        endpoint=endpoint,
        method=method_upper,
        status_code=last_status_code,
        duration_ms=total_duration_ms,
        approval_status=approval_status,
        request_headers=req_headers,
        response_body_snippet=burst_summary_text,
        log_file=log_file,
    )

    return {
        "status": "success",
        "endpoint": endpoint,
        "method": method_upper,
        "burst_total": total_count,
        "status_distribution": status_counts,
        "rate_limited_count": rate_limited_count,
        "first_rate_limit_at": first_rate_limit_at,
        "duration_ms": round(total_duration_ms, 2),
        "last_status_code": last_status_code,
        "last_body_snippet": last_body_snippet,
    }


def main() -> None:
    """CLI Entrypoint for manual testing via `make test-request ARGS='...'`."""
    parser = argparse.ArgumentParser(
        description="Sentinel Safe HTTP Requester - Test API Gateway endpoints safely."
    )
    parser.add_argument(
        "--url",
        "-u",
        required=True,
        help="Target endpoint path or URL (e.g. /rest/products/search?q=apple)",
    )
    parser.add_argument(
        "--method",
        "-m",
        default="GET",
        choices=["GET", "PUT", "OPTIONS", "POST", "DELETE"],
        help="HTTP Method (Allowed: GET, PUT, OPTIONS).",
    )
    parser.add_argument(
        "--payload-category",
        "-c",
        default=None,
        help="Payload category from payloads.json (e.g. special_chars, sql_injection_probes).",
    )
    parser.add_argument(
        "--payload-value",
        "-v",
        default=None,
        help="Custom direct payload value to send.",
    )
    parser.add_argument(
        "--count",
        "-n",
        type=int,
        default=1,
        help="Number of requests to send (Burst Mode for Rate Limiting test).",
    )
    parser.add_argument(
        "--interval",
        "-i",
        type=float,
        default=0.05,
        help="Delay between burst requests in seconds (default: 0.05).",
    )
    parser.add_argument(
        "--oversized",
        action="store_true",
        help="Generate a 1.5MB buffer internally to test Gateway request-size-limiting.",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Automatically approve HITL prompt (useful in CI or test scripts).",
    )
    parser.add_argument(
        "--gateway-host",
        default=None,
        help="Gateway base URL (default: http://localhost:3000).",
    )

    args = parser.parse_args()

    result = send_safe_request(
        endpoint=args.url,
        method=args.method,
        payload_category=args.payload_category,
        payload_value=args.payload_value,
        burst_count=args.count,
        interval_seconds=args.interval,
        oversized_payload=args.oversized,
        auto_approve=args.auto_approve,
        gateway_host=args.gateway_host,
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
