# Báo Cáo Kỹ Thuật Tuần 5: Kiến Trúc Kong API Gateway Client-First & Cơ Chế Khóa Fallback Allowlist

## 1. Tổng Quan Mục Tiêu & Kiến Trúc Bảo Mật

Trong khuôn khổ **Project Sentinel**, việc đưa **Kong API Gateway (`kong:3.6.1`)** đứng trước ứng dụng mục tiêu **OWASP Juice Shop (`v20.1.1`)** nhằm thực hiện các mục tiêu bảo mật cốt lõi:
1. **Phân quyền Client-First (Consumer-Scoped Authorization)**: Nhận diện và áp dụng chính sách bảo vệ, giới hạn tốc độ (Rate Limiting) riêng biệt cho 3 nhóm đối tượng: AI Security Agent (`ai-agent`), Khách vãng lai (`anonymous-user`) và Người dùng đăng nhập (`juice-shop-users`).
2. **Triệt tiêu lỗ hổng Fallback Wildcard `/`**: Ngăn chặn kẻ tấn công lợi dụng route gốc của Single Page Application để bypass Allowlist và truy cập trái phép vào các endpoint nhạy cảm (`/ftp`, `/encryptionkeys`, `/support/logs`, `/rest/admin/*`).
3. **Cô lập hạ tầng mạng (Network Isolation)**: Khi chạy có Gateway, container Juice Shop bị ẩn hoàn toàn trong mạng nội bộ Docker và chỉ có thể truy cập thông qua cổng Proxy của Kong.

---

## 2. Ma Trận Phân Quyền Client-First & Cấu Trúc Allowlist

Hệ thống quản lý phân quyền thông qua `src/gateway/allowlist.json` với ma trận 3 nhóm Client:

| Nhóm Client | Consumer Định Danh | Phương Thức Xác Thực | Nhóm ACL | Rate Limit | Mục Đích Sử Dụng |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **`agent`** | `ai-agent` | `key-auth` (`x-api-key`) | `agent-group` | 20 req/phút | Dành riêng cho AI Security Agent thăm dò các điểm nghi vấn. |
| **`guest`** | `anonymous-user` | `anonymous` (Key-Auth Fallback) | `guest-group` | 60 req/phút | Dành cho người dùng công khai duyệt sản phẩm, đăng ký tài khoản. |
| **`user`** | `juice-shop-users` | `jwt` (Bearer Token RSA) | `user-group` | 100 req/phút | Dành cho người dùng đã đăng nhập thao tác giỏ hàng, đặt hàng, profile. |

---

## 3. Cơ Chế Khóa Fallback Route Gốc (Kết Hợp Giải Pháp 1 + Giải Pháp 2)

Để đảm bảo giao diện Angular SPA hiển thị 100% bình thường mà **không mở toang wildcard `/`**:

```mermaid
flowchart TD
    Request[HTTP Request tới Gateway :3000] --> CheckRoute{Khớp Route Cụ Thể?}
    
    CheckRoute -->|Path là exact / hoặc /index.html| RouteRoot[route-spa-root<br/>Regex: ~^/$<br/>Chỉ mở GET/HEAD] --> AllowRoot[Trả về index.html]
    CheckRoute -->|Path là bundle static tại root hoặc /assets, /vendor| RouteAssets[route-spa-assets<br/>Regex: ~^/.*.(js|css|ico|png|svg|woff2)<br/>Chỉ mở GET/HEAD] --> AllowAssets[Tải CSS/JS/Font/Image]
    CheckRoute -->|Path khớp API Allowlist /api/*, /rest/*| RouteAPI[API Routes Hợp Lệ<br/>Xác thực Key/JWT/ACL] --> AllowAPI[Proxy vào Juice Shop]
    CheckRoute -->|Không khớp: /ftp, /metrics, /encryptionkeys, /rest/admin/*| BlockAll[KONG GATEWAY CHẶN ĐỨNG<br/>403 Forbidden / 404 Not Found]
```

- **`route-spa-root` (Giải Pháp 1 - Exact Regex `~^/$`)**: Chỉ chấp nhận duy nhất trang chủ gốc `/` và `/index.html` cho các phương thức đọc (`GET`, `HEAD`, `OPTIONS`).
- **`route-spa-assets` (Giải Pháp 2 - Root File Bundle Regex)**: Chỉ cho phép tải các bundle tĩnh có phần mở rộng `.js`, `.css`, `.ico`, `.png`, `.svg`, `.woff2`, `.map` tại thư mục gốc và 2 thư mục tĩnh `/assets`, `/vendor`.
- **Hiệu quả**: Mọi request tới các file/endpoint nguy hiểm như `/ftp/legal.md`, `/encryptionkeys/jwt.pub`, `/support/logs/access.log` đều **bị chặn 100% ngay tại Gateway**.

---

## 4. Phân Định Rõ Ràng Các Nhóm API Key

Hệ thống phân định độc lập 3 nhóm khóa môi trường trong `.env`:
1. **`KONG_VAULT_ENV_AGENT_API_KEY` (Server-side)**: Khóa bí mật đăng ký trên Kong Gateway để nhận diện consumer `ai-agent`.
2. **`AGENT_API_KEY` (Client-side)**: Khóa bí mật nạp vào công cụ `SafeRequester` (`src/gateway/safe_requester.py`) để Agent gửi kèm trong HTTP Header `x-api-key`.
3. **`LLM_API_KEY` (AI Provider)**: Khóa gọi mô hình ngôn ngữ lớn (Qwen / OpenAI / Claude).

---

## 5. Cơ Chế Chuyển Đổi Cổng Thông Minh (Single Port Switch `:3000`)

Cả 2 chế độ vận hành đều dùng chung cổng `http://localhost:3000` trên máy host để phục vụ đối sánh thực nghiệm:

- **Chế độ 1 — Standalone Target (`make target-up`)**: Juice Shop ánh xạ trực tiếp `127.0.0.1:3000:3000` (Không có Gateway bảo vệ).
- **Chế độ 2 — Gateway Protected (`make gateway-up`)**: Kong Gateway ánh xạ `127.0.0.1:3000:8000` (Proxy) và `127.0.0.1:8001:8001` (Admin API). Container Juice Shop bị ẩn hoàn toàn vào mạng nội bộ Docker (`sentinel-security`).

---

## 6. Bộ Biên Dịch Boot-Time Lua (`render_config.lua`)

Khi Kong Gateway khởi động, lệnh boot-time thực thi script LuaJIT `src/gateway/render_config.lua`:
- Đọc và phân tích `allowlist.json` bằng thư viện `cjson`.
- Tự động chuyển đổi các path cho phép của `agent` thành bảng tra cứu in-memory `["/path"] = true`.
- Nạp khóa RSA public key và thay thế các biến môi trường vào template `kong.yml.template`, xuất ra `/tmp/kong.yml`.
- Tích hợp cơ chế Fallback an toàn: Tự động kích hoạt Default Fallback Allowlist nếu tệp cấu hình bị rỗng hoặc lỗi cú pháp.

---

## 7. Kết Quả Kiểm Thử Thực Nghiệm

Toàn bộ hệ thống kiểm thử đã được chạy và xác nhận đạt chuẩn 100%:

| Bộ Test Suite | Số Lượng Tests | Kết Quả | Nội Dung Xác Minh |
| :--- | :---: | :---: | :--- |
| **`tests/gateway/test_gateway_config.py`** | 7 | **100% PASS** | Kiểm tra cú pháp `allowlist.json`, xác nhận không có wildcard `/` nguy hiểm, kiểm tra template `kong.yml.template`, script Lua, biến môi trường và Compose override. |
| **`tests/guardrails/` (Milestone 1)** | 16 | **100% PASS** | Khử khuẩn PII/Secret và phòng vệ Prompt Injection hoạt động chính xác. |
| **`tests/agent/` (Regression)** | 34 | **100% PASS** | Toàn bộ luồng phân tích và nạp prompt của AI Agent tương thích hoàn toàn. |
| **Toàn bộ Repository (`pytest tests/`)** | 331 | **100% PASS** | Đảm bảo tính toàn vẹn của tất cả các module. |
| **Kiểm tra Định dạng (`make quality`)** | Clean | **100% PASS** | Đạt chuẩn Ruff lint, Docker compose config và Contract scripts. |
