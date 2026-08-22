"""Project Sentinel - Human-in-the-Loop (HITL) Risk Evaluator and Approval Engine.

Module: src/gateway/hitl.py
Mục đích:
    Cung cấp cơ chế đánh giá rủi ro trước khi phát tán request và chốt chặn phê duyệt
    thủ công (Human-in-the-Loop) với cơ chế Timeout 120s (Default to Reject).
    - Phân loại rủi ro: LOW (tự động thực thi), MEDIUM (yêu cầu duyệt), HIGH (yêu cầu duyệt + cảnh báo tài nguyên).
    - Hỗ trợ môi trường CI/CD (biến môi trường CI_MODE=true hoặc AUTO_APPROVE=true).
    - Đảm bảo an toàn tối đa: khi timeout hoặc xảy ra lỗi nhập liệu, mặc định từ chối (Fail-Safe).
"""

from __future__ import annotations

import os
import select
import sys
from typing import Any

DEFAULT_HITL_TIMEOUT_SECONDS = 120.0


def assess_request_risk(
    method: str,
    endpoint: str,
    payload_category: str | None = None,
    burst_count: int = 1,
    oversized_payload: bool = False,
) -> dict[str, Any]:
    """Evaluate the operational and security risk level of a proposed HTTP test request.

    Args:
        method: HTTP method (e.g. 'GET', 'PUT', 'OPTIONS').
        endpoint: Target HTTP path (e.g. '/api/Products', '/rest/products/1/reviews').
        payload_category: Category identifier from payloads.json (e.g. 'sql_injection_probes').
        burst_count: Total number of requests planned in rapid succession (Burst Mode).
        oversized_payload: Boolean flag indicating if a 1.5MB test payload will be generated.

    Returns:
        dict[str, Any]: Assessment summary containing:
            - 'requires_approval' (bool): True if human confirmation is mandatory.
            - 'risk_level' (str): 'LOW', 'MEDIUM', or 'HIGH'.
            - 'risk_factors' (list[str]): Bullet points explaining why approval is required.
            - 'endpoint' (str): Cleaned endpoint path.
            - 'method' (str): Uppercase HTTP method.
            - 'payload_category' (str | None): Payload classification.
            - 'burst_count' (int): Request count.
            - 'oversized_payload' (bool): Payload size flag.
            - 'purpose' (str): Descriptive test objective.
    """
    method_upper = method.strip().upper() if isinstance(method, str) else "UNKNOWN"
    clean_endpoint = endpoint.strip() if isinstance(endpoint, str) else "/"
    clean_cat = payload_category.strip().lower() if isinstance(payload_category, str) else None
    count = max(1, int(burst_count)) if isinstance(burst_count, (int, float)) else 1

    risk_factors: list[str] = []

    # 1. Evaluate High Risk criteria
    if oversized_payload:
        risk_factors.append("Payload ngoại cỡ 1.5MB (kiểm thử giới hạn 1MB request-size-limiting của Gateway)")

    if count > 20:
        risk_factors.append(
            f"Số lượng request gửi liên tiếp ({count} reqs) vượt ngưỡng giới hạn tần suất 20 req/min của Agent"
        )

    # 2. Evaluate Medium Risk criteria
    if method_upper == "PUT":
        risk_factors.append(f"Phương thức {method_upper} có khả năng ghi đè/tạo dữ liệu mới trên máy chủ mục tiêu")

    if 5 < count <= 20:
        risk_factors.append(f"Gửi đồng thời {count} requests liên tiếp (Burst Mode)")

    medium_risk_payloads = {
        "special_chars",
        "query_param_injection",
        "sql_injection_probes",
        "cross_site_scripting_probes",
    }
    if clean_cat in medium_risk_payloads:
        risk_factors.append(f"Nhóm payload thăm dò bảo mật đặc biệt ('{clean_cat}')")

    # 3. Determine Overall Risk Level & Approval Requirement
    if oversized_payload or count > 20:
        risk_level = "HIGH"
        requires_approval = True
    elif len(risk_factors) > 0:
        risk_level = "MEDIUM"
        requires_approval = True
    else:
        risk_level = "LOW"
        requires_approval = False

    # 4. Formulate purpose description
    if oversized_payload:
        purpose = "Kiểm chứng Gateway kích hoạt mã 413 Request Entity Too Large khi nhận payload 1.5MB"
    elif count > 1:
        purpose = f"Kiểm chứng Gateway kích hoạt mã 429 Too Many Requests khi gửi {count} requests liên tiếp"
    elif method_upper == "PUT":
        purpose = f"Kiểm thử gửi dữ liệu kiểm toán {method_upper} tới {clean_endpoint}"
    elif method_upper == "OPTIONS":
        purpose = f"Kiểm tra CORS Preflight và danh sách HTTP Methods hỗ trợ trên {clean_endpoint}"
    else:
        purpose = f"Kiểm thử an toàn kết nối HTTP {method_upper} tới {clean_endpoint}"

    return {
        "requires_approval": requires_approval,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "endpoint": clean_endpoint,
        "method": method_upper,
        "payload_category": clean_cat,
        "burst_count": count,
        "oversized_payload": oversized_payload,
        "purpose": purpose,
    }


def prompt_cli_approval(
    assessment: dict[str, Any],
    auto_approve: bool = False,
    timeout_seconds: float = DEFAULT_HITL_TIMEOUT_SECONDS,
) -> bool:
    """Prompt the human operator on the CLI to approve or reject a risky security action.

    Args:
        assessment: Risk analysis dictionary returned by assess_request_risk().
        auto_approve: If True, immediately approve without interactive prompt (for tests/CI).
        timeout_seconds: Maximum duration in seconds to wait for input. Defaults to 120.0 (2 minutes).

    Returns:
        bool: True if approved by user/CI, False if rejected, interrupted, or timed out.

    Behavior:
        - Automatically approves if CI_MODE or AUTO_APPROVE environment variables are set to 'true'.
        - On interactive terminals, displays an ANSI-formatted risk banner and awaits 'y'/'yes'.
        - If timeout expires before receiving input, displays a timeout notice and safely returns False.
    """
    # 1. Check CI Mode / Auto-approve flags
    env_ci = os.getenv("CI_MODE", "").strip().lower() in ("true", "1", "yes")
    env_auto = os.getenv("AUTO_APPROVE", "").strip().lower() in ("true", "1", "yes")

    if auto_approve or env_ci or env_auto:
        print(
            f"\n[HITL AUTO-APPROVED] Yêu cầu '{assessment.get('method')} {assessment.get('endpoint')}' "
            "được tự động phê duyệt (CI/Testing Mode)."
        )
        return True

    # 2. Display interactive approval banner
    print("\n" + "=" * 70)
    print("⚠️  [HUMAN-IN-THE-LOOP] YÊU CẦU PHÊ DUYỆT HÀNH ĐỘNG KIỂM THỬ BẢO MẬT")
    print("=" * 70)
    print(f"- Mục tiêu kiểm thử:   {assessment.get('method')} {assessment.get('endpoint')}")
    print(f"- Mức độ rủi ro:       {assessment.get('risk_level')}")
    print(f"- Số lượng request:    {assessment.get('burst_count')}")
    print(f"- Nhóm Payload:        {assessment.get('payload_category') or 'Mặc định/None'}")
    print(f"- Mục đích kiểm tra:   {assessment.get('purpose')}")
    print("- Các yếu tố rủi ro:")
    for factor in assessment.get("risk_factors", []):
        print(f"   • {factor}")
    print("-" * 70)
    print(f"⏱️  Thời gian chờ phản hồi tối đa: {int(timeout_seconds)} giây (2 phút). Quá hạn sẽ tự động Từ chối.")
    sys.stdout.write("👉 Bạn có CHẤP THUẬN gửi request này không? (y/N): ")
    sys.stdout.flush()

    # 3. Non-blocking input waiting with select
    try:
        if sys.stdin.isatty():
            ready, _, _ = select.select([sys.stdin], [], [], timeout_seconds)
            if ready:
                user_input = sys.stdin.readline().strip().lower()
            else:
                print("\n🛑 [HITL TIMEOUT] Quá thời gian chờ xác nhận (120s / 2 phút). Tự động từ chối (Default to Reject) vì lý do an toàn.\n")
                return False
        else:
            # Non-interactive fallback (e.g. piped stdin)
            user_input = sys.stdin.readline().strip().lower()

        if user_input in ("y", "yes"):
            print("✅ [HITL APPROVED] Người dùng đã phê duyệt. Bắt đầu thực thi request...\n")
            return True
        else:
            print("🛑 [HITL REJECTED] Người dùng đã TỪ CHỐI thực thi. Hủy bỏ request an toàn.\n")
            return False

    except (EOFError, KeyboardInterrupt):
        print("\n🛑 [HITL REJECTED] Ngắt tương tác người dùng (Default to Reject).\n")
        return False
