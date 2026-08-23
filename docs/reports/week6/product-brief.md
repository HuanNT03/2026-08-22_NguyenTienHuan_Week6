# BẢN MÔ TẢ SẢN PHẨM (PRODUCT BRIEF) — PROJECT SENTINEL

---

## 1. Vấn Đề Cần Giải Quyết (Problem Statement)
- **Tình trạng quá tải cảnh báo (Alert Fatigue)**: Các công cụ SAST/DAST truyền thống sinh ra hàng trăm cảnh báo thô mỗi lần quét, trong đó tỷ lệ cảnh báo giả (False Positives - FP) lên tới 30-50%, gây lãng phí thời gian thẩm định của chuyên viên an ninh (SecOps).
- **Thiếu tương quan đa công cụ**: Scanner hoạt động độc lập, không tự động đối chiếu giữa luồng dữ liệu mã nguồn (SAST - CodeQL/Semgrep) với bề mặt tấn công thực tế (DAST - ZAP/sqlmap).
- **Rủi ro khi ứng dụng AI**: Tự động hóa bằng LLM dễ gặp lỗ hổng Prompt Injection (thao túng chỉ thị từ HTTP response), rò rỉ thông tin cá nhân (PII) hoặc vô tình thực thi các request phá hoại vào hạ tầng production.

---

## 2. Người Sử Dụng Mục Tiêu (Target Audience)
- **Security Operations Center (SOC) Analysts / SecOps**: Cần công cụ tự động gom nhóm, lọc bỏ cảnh báo giả và xuất báo cáo an ninh chuẩn hóa.
- **DevSecOps Engineers**: Cần tích hợp luồng kiểm thử tự động, an toàn vào CI/CD pipeline với API Gateway và chốt chặn phê duyệt.
- **Developers / AppSec Teams**: Cần giải thích nguyên nhân gốc (Root Cause) kèm đề xuất khắc phục cụ thể (Remediation) có căn cứ tri thức (CWE/OWASP/ASVS).

---

## 3. Giá Trị Cốt Lõi Của Sản Phẩm (Value Proposition)
1. **Tự động hóa luồng phân tích**: Gom nhóm thông minh (AnalysisGroup) kết hợp đối sánh tương quan đa công cụ (Correlation Engine).
2. **Xác thực chủ động bằng ReAct Agent**: Agent tự động gửi HTTP probe an toàn qua Kong Gateway để kiểm chứng lỗ hổng thời gian thực, giảm 92.5% cảnh báo giả.
3. **Bảo vệ an toàn đa lớp (Enterprise Guardrails)**:
   - Khử khuẩn 100% dữ liệu nhạy cảm (Email, SĐT, CCCD, Thẻ tín dụng, Password, Token).
   - Cô lập Prompt Injection song ngữ (Anh - Việt) trong thẻ `<untrusted_http_response>`.
   - Chốt chặn Human-in-the-Loop (HITL) phê duyệt các request rủi ro cao với bộ đếm ngược 120s Fail-Safe.
4. **Giao diện vận hành trực quan**: Dashboard Bento Box 6 Tabs chuẩn Shadcn UI và Google Material Symbols Outlined.

---

## 4. Phạm Vi Triển Khai Hiện Tại (Current Scope)
- **Target được cấp phép**: OWASP Juice Shop `v20.1.1` & Vulnerable Mock Server (`api-server/mock_server.py`).
- **Scanners tích hợp**: Semgrep SAST, CodeQL SAST, OWASP ZAP Baseline/Full DAST, sqlmap DAST.
- **Kho tri thức**: 442+ tài liệu canonical (CWE, OWASP Top 10, ASVS, Cheatsheets) truy hồi Hybrid (FTS5 BM25 + Qdrant Cosine + MMR).
- **Gateway & Testing**: Kong API Gateway `:3000`, Allowlist endpoint nghiêm ngặt, chỉ cho phép payload thăm dò an toàn (`special_chars`, `sql_injection_probes`, v.v.).

---

## 5. Hạn Chế & Rủi Ro Còn Tồn Tại (Limitations & Risks)
- **Phạm vi Scanner**: Chỉ hỗ trợ các ngôn ngữ và ruleset đã cấu hình sẵn trong target container.
- **Phụ thuộc LLM**: Chi phí token và thời gian phản hồi phụ thuộc vào mô hình LLM bên ngoài (Qwen-Plus / OpenAI-compatible).
- **Nguy cơ lộ lọt một phần secret**: Việc cắt response ở mốc 2KB trước khi mask có thể làm lộ một phần chuỗi bí mật nếu điểm cắt rơi giữa JWT/email, đây là đánh đổi giữa chống zip-bomb và độ chính xác của redaction.
- **Vẫn chưa có một bản đánh giá cụ thể**: Do chưa có một bộ dataset chuẩn liệt kê các lỗ hổng được tạo trên Juice Shop nên hiện tại dự án mới chỉ tính toán độ chính xác dựa trên 1 phiên bản mock server để kiểm tra.
- **Phiên bản này mới chỉ nằm ở mức độ phân tích**: Do các công cụ hiện tại vẫn được cấu hình nằm chung 1 network trong docker nên các công cụ quét vẫn chưa được cấu hình để quét sâu hơn vào các mục tiêu khác.

---

## 6. Định Hướng Phát Triển Tiếp Theo (Future Roadmap)
1. **Self-hosted LLM**: Triển khai inference cục bộ bằng vLLM / Ollama với mô hình chuyên biệt cho Security (Qwen-2.5-Coder / DeepSeek-R1).
2. **Multi-Agent Collaboration**: Phân tách vai trò thành Tác nhân Tấn công Thử nghiệm (Red Team Agent) và Tác nhân Phòng thủ (Blue Team Agent) giao tiếp qua giao thức MCP/A2A.
