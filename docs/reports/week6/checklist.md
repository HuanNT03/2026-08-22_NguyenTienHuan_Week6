## Sản phẩm bàn giao cuối cùng

## 1. Mã nguồn

Bao gồm:

- [x] Cấu hình Cl.
  - Đường dẫn: `.github/workflows/ci.yml`
- [x] Công cụ chuẩn hóa dữ liệu.
  - Đường dẫn: `src/normalizers/`
- [x] Kho tri thức.
  - Đường dẫn: `knowledge-base/` và `src/retrieval/`
- [x] Security Analysis Agent.
  - Đường dẫn: `src/agent/`
- [x] Python Tool gửi request.
  - Đường dẫn: `src/agent/tools.py` và `src/gateway/safe_requester.py`
- [x] Guardrails.
  - Đường dẫn:
    - **Gateway Guardrails**: `src/gateway/allowlist.json` (Endpoint Allowlist), `src/gateway/payloads.json` (Safe Payloads Allowlist), `src/gateway/hitl.py` (Human-in-the-Loop 120s Fail-Safe), `src/gateway/safe_requester.py` (Rate Limit & Response Length Guard).
    - **Data Sanitization & Injection Guardrails**: `src/guardrails/injection.py` (Phát hiện Prompt Injection song ngữ Anh - Việt) và `src/guardrails/redactor.py` (Khử khuẩn PII, mật khẩu, JWT token).
    - **System Prompt Guardrails**: `src/agent/prompts/system_v2.md` (Quy tắc cách ly `<untrusted_http_response>`, chống chỉ thị ghi đè SYSTEM OVERRIDE và ép buộc Schema Contract).
- [x] Chức năng che dữ liệu.
  - Đường dẫn: `src/guardrails/redactor.py`
- [x] Docker Compose.
  - Đường dẫn: `docker-compose.yml` và `docker-compose.gateway.yml`

## 2. Tài liệu kỹ thuật

Bao gồm:

- [x] Kiến trúc hệ thống.
  - Đường dẫn: `docs/reports/week6/react-agent-architecture-report.md` và `README.md`
- [x] Hướng dẫn cài đặt.
  - Đường dẫn: `README.md`
- [x] Hướng dẫn chạy demo.
  - Đường dẫn: `README.md` (Mục Hướng dẫn Chạy Demo Thực Nghiệm Với Mock Server & Web UI), `docs/reports/week6/react-agent-evaluation-report.md` (Mục 6) và `scripts/live_mock_probe_demo.py`
- [x] Các giới hạn của hệ thống.
  - Đường dẫn: `docs/reports/week6/product-brief.md` (Mục 5) và `docs/reports/week6/react-agent-evaluation-report.md` (Mục 7.1)
- [x] Các quyết định thiết kế chính.
  - Đường dẫn: `docs/reports/week6/react-agent-architecture-report.md` (Mục 4)
- [x] Các rủi ro bảo mật còn tồn tại.
  - Đường dẫn: `docs/reports/week6/product-brief.md` (Mục 5) và `docs/reports/week6/react-agent-evaluation-report.md` (Mục 7.2)

## 3. Báo cáo kết quả

Bao gồm:

- [x] Các lỗ hổng đã phát hiện.
  - Đường dẫn: `docs/reports/week6/react-agent-evaluation-report.md` (Mục 2 và Mục 5)
- [x] Các trường hợp Agent phân tích đúng.
  - Đường dẫn: `docs/reports/week6/react-agent-evaluation-report.md` (Mục 3.1)
- [x] Các trường hợp Agent phân tích sai.
  - Đường dẫn: `docs/reports/week6/react-agent-evaluation-report.md` (Mục 3.2)
- [x] False Positive và False Negative.
  - Đường dẫn: `docs/reports/week6/react-agent-evaluation-report.md` (Mục 4)
- [x] Đề xuất cải tiến.
  - Đường dẫn: `docs/reports/week6/react-agent-evaluation-report.md` (Mục 7.3) và `docs/reports/week6/product-brief.md` (Mục 6)

## 4. Bản trình diễn

Bản demo cần thể hiện:

- [x] Một lần chạy công cụ quét.
  - Đường dẫn: `Makefile` (lệnh `make sast`, `make dast`, `make dast-mock`) và `frontend/app.py` (Tab 1)
- [x] Agent tạo báo cáo.
  - Đường dẫn: `src/agent/orchestrator.py` và `frontend/app.py` (Tab 5)
- [x] Agent đề xuất request kiểm tra.
  - Đường dẫn: `schemas/security_analysis_report.schema.json` (trường `proposed_test_request`) và `frontend/app.py` (Tab 5)
- [x] Người dùng Approve hoặc Reject.
  - Đường dẫn: `frontend/components/hitl_queue.py` và `frontend/app.py` (Hàng đợi phê duyệt HITL Sidebar)
- [x] Request đi qua API Gateway.
  - Đường dẫn: `docker-compose.gateway.yml` và `frontend/app.py` (Tab 4 và Tab 6)
- [x] Prompt Injection bị chặn.
  - Đường dẫn: `tests/guardrails/test_vulnerable_mock_guardrails.py` và `frontend/app.py` (Tab 6)
- [x] Dữ liệu nhạy cảm bị che.
  - Đường dẫn: `src/guardrails/redactor.py` và `frontend/app.py` (Tab 4 và Tab 6)

## 5. Bản mô tả sản phẩm ngắn

Tài liệu từ một đến hai trang gồm:

- [x] Vấn đề cần giải quyết.
  - Đường dẫn: `docs/reports/week6/product-brief.md` (Mục 1)
- [x] Người sử dụng.
  - Đường dẫn: `docs/reports/week6/product-brief.md` (Mục 2)
- [x] Giá trị của sản phẩm.
  - Đường dẫn: `docs/reports/week6/product-brief.md` (Mục 3)
- [x] Phạm vi hiện tại.
  - Đường dẫn: `docs/reports/week6/product-brief.md` (Mục 4)
- [x] Hạn chế.
  - Đường dẫn: `docs/reports/week6/product-brief.md` (Mục 5)
- [x] Hướng phát triển tiếp theo.
  - Đường dẫn: `docs/reports/week6/product-brief.md` (Mục 6)
