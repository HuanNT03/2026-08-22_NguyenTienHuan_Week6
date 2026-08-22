# Báo Cáo Kỹ Thuật Tuần 5: Kiến Trúc Kong API Gateway Client-First & Cơ Chế Tự Động Hóa Allowlist

## 1. Tổng Quan Mục Tiêu & Kiến Trúc Bảo Mật

Trong khuôn khổ **Project Sentinel**, việc đưa **Kong API Gateway (`kong:3.6.1`)** đứng trước ứng dụng mục tiêu **OWASP Juice Shop (`v20.1.1`)** nhằm thực hiện 3 trụ cột an ninh:
1. **Nguồn chân lý duy nhất (Single Source of Truth)**: Toàn bộ danh mục route, quyền truy cập và giới hạn tốc độ được quản lý tập trung tại `src/gateway/allowlist.json`. Khi cần bổ sung endpoint mới, kỹ sư chỉ cần cập nhật một tệp JSON duy nhất.
2. **Phân quyền Client-First (Consumer-Scoped Authorization)**: Nhận diện và áp dụng chính sách bảo vệ riêng biệt cho 3 nhóm đối tượng: AI Security Agent (`ai-agent`), Khách vãng lai (`anonymous-user`) và Người dùng đăng nhập (`juice-shop-users`).
3. **Triệt tiêu lỗ hổng Fallback Wildcard `/`**: Ngăn chặn kẻ tấn công lợi dụng route gốc SPA để bypass Allowlist và truy cập trái phép vào các endpoint nhạy cảm (`/ftp`, `/encryptionkeys`, `/support/logs`, `/rest/admin/*`).

---

## 2. Sơ Đồ Kiến Trúc Biên Dịch Boot-Time & Luồng Xử Lý Request

```mermaid
flowchart TD
    subgraph SingleSourceOfTruth [1. Single Source of Truth & Environment]
        AllowlistJSON["src/gateway/allowlist.json<br/>(15 Routes, 3 Clients, Rate Limits)"]
        TemplateYML["src/gateway/kong.yml.template<br/>(Chứa các Placeholders)"]
        EnvKey["Biến Môi Trường .env<br/>KONG_VAULT_ENV_AGENT_API_KEY"]
    end

    subgraph BootTimeCompilation [2. Bộ Biên Dịch Boot-Time LuaJIT]
        LuaCompiler["src/gateway/render_config.lua<br/>(Khởi chạy trước khi Kong Daemon start)"]
        GenRoutes["Tự động sinh khối YAML Routes<br/>${GENERATED_ROUTES_YAML}"]
        GenAgentLUT["Tự động sinh bảng tra cứu Agent O(1)<br/>${ALLOWED_PATHS_LUA}"]
        InjectKey["Nạp API Key vào Consumer<br/>${AGENT_API_KEY}"]
        OutputYML["Xuất tệp hoàn chỉnh: /tmp/kong.yml"]
    end

    subgraph KongRuntimeEngine [3. Kong Gateway Engine (DB-less Mode)]
        KongLoad["Kong nạp /tmp/kong.yml vào RAM"]
        
        Req[HTTP Request tới Gateway :3000] --> PreFunc{Lua Pre-Function Check}
        
        PreFunc -->|Có x-api-key| CheckAgent{Key Hợp Lệ & Path thuộc Agent LUT?}
        CheckAgent -->|Không hợp lệ / Không thuộc allowlist| BlockAgent[401 Unauthorized / 403 Forbidden]
        CheckAgent -->|Hợp lệ| ConsumerAgent[Consumer: ai-agent<br/>Rate Limit: 20 req/min]
        
        PreFunc -->|Không có x-api-key| MatchRoute{Khớp Route trong YAML?}
        MatchRoute -->|Không khớp: /ftp, /metrics, /encryptionkeys| BlockPublic[404 Not Found / 403 Forbidden]
        MatchRoute -->|Khớp Route| KeyAuth[Key-Auth: Gán Consumer anonymous-user]
        KeyAuth --> ApplyRouteRate[Áp dụng Route-level Rate Limit<br/>Login: 30, Register: 20, SPA: 60-100]
        
        ConsumerAgent --> ProxyTarget[Forward vào Juice Shop :3000]
        ApplyRouteRate --> ProxyTarget
        
        ProxyTarget --> JuiceShopNative[Juice Shop Backend<br/>Tự xác thực Bearer JWT -> 401 nếu thiếu token]
    end

    AllowlistJSON --> LuaCompiler
    TemplateYML --> LuaCompiler
    EnvKey --> LuaCompiler
    
    LuaCompiler --> GenRoutes --> OutputYML
    LuaCompiler --> GenAgentLUT --> OutputYML
    LuaCompiler --> InjectKey --> OutputYML
    OutputYML --> KongLoad
```

---

## 3. Cơ Chế Nạp Dữ Liệu Tự Động (Data Ingestion Mechanisms)

### 3.1. Cơ chế Tạo Route Tự Động (`${GENERATED_ROUTES_YAML}`)
- `render_config.lua` phân tích mảng `routes` trong `src/gateway/allowlist.json`.
- Với mỗi route, script tự động sinh cấu trúc YAML chuẩn cho Kong:
  - `name`: Tên route định danh (ví dụ `route-products-browse`, `route-user-login`).
  - `paths`: Danh sách đường dẫn hoặc biểu thức chính quy (ví dụ `~^/$`, `/index.html`, `/assets`).
  - `methods`: Danh sách phương thức HTTP cho phép (`GET`, `POST`, `OPTIONS`...).
  - `strip_path: false`: Giữ nguyên URL gốc khi chuyển tiếp vào backend.
  - `plugins`: Tự động gắn plugin `rate-limiting` riêng biệt cho từng route.
- Toàn bộ khối YAML được điền vào vị trí `${GENERATED_ROUTES_YAML}` trong `kong.yml.template`.

### 3.2. Cơ chế Nạp Dữ Liệu Phân Quyền (`${ALLOWED_PATHS_LUA}`)
- Script duyệt qua các route có `allow` chứa `"agent"`.
- Trích xuất danh sách endpoint an toàn và chuyển đổi thành bảng tra cứu in-memory của Lua:
  ```lua
  local allowed_paths = { ["/api/Products"] = true, ["/rest/products/search"] = true, ["/rest/user/login"] = true, ["/rest/user/whoami"] = true }
  ```
- Bảng này được nhúng trực tiếp vào plugin `pre-function`. Khi Agent gửi request có kèm `x-api-key`, plugin kiểm tra path với độ phức tạp $O(1)$. Nếu URL không có trong bảng $\rightarrow$ trả về `403 Forbidden` ngay lập tức.
- **Xác thực Token Người dùng**: Bỏ ràng buộc `authorization: ["~^Bearer "]` tại Kong Gateway để chuyển giao việc kiểm tra JWT cho middleware `express-jwt` của Juice Shop. Điều này đảm bảo:
  1. Trả về đúng mã chuẩn `401 Unauthorized` thay vì `404 Not Found`.
  2. Cho phép AI Agent và DAST ZAP quét và kiểm thử chính xác các lỗ hổng Broken Authentication / IDOR / BOLA.

### 3.3. Cơ chế Phân Tầng Giới Hạn Tốc Độ (Multi-Tier Rate Limiting)

Kong Gateway áp dụng thứ tự ưu tiên plugin (Plugin Precedence) chặt chẽ:
1. **Tầng Consumer (Consumer-scoped Rate Limit)**:
   - Consumer `ai-agent` được gán plugin `rate-limiting` mức **20 requests/phút** tại cấp độ consumer. Giới hạn này có độ ưu tiên cao nhất và ghi đè mọi rate limit của route, đảm bảo AI Agent luôn tuân thủ ngưỡng an toàn của hệ thống.
2. **Tầng Route (Route-level Rate Limit)**:
   - Áp dụng cho khách vãng lai (`anonymous-user`) và người dùng thông thường (`juice-shop-users`):
     - `route-user-login`: **30 req/phút** (Chống tấn công dò mật khẩu Brute-force).
     - `route-guest-register`, `route-reset-password`: **20 req/phút** (Chống tạo tài khoản rác Anti-Spam).
     - `route-spa-root`: **60 req/phút** (Duyệt trang chủ).
     - `route-spa-assets`: **100 req/phút** (Tải tài nguyên tĩnh CSS/JS).
     - `route-profile-image-upload`: **50 req/phút** (Giới hạn tải tệp).

---

## 4. Ma Trận Cấu Hình Client-First & Cơ Chế Khóa Fallback

| Nhóm Client | Consumer | Auth Method | Rate Limit | Mục Đích Sử Dụng |
| :--- | :--- | :--- | :---: | :--- |
| **`agent`** | `ai-agent` | `key-auth` (`x-api-key`) | 20 req/phút | Dành riêng cho AI Security Agent thăm dò các điểm nghi vấn. |
| **`guest`** | `anonymous-user` | `anonymous` (Key-Auth Fallback) | 60 req/phút | Dành cho người dùng công khai duyệt sản phẩm, đăng ký tài khoản. |
| **`user`** | `juice-shop-users` | `jwt` (Native Juice Shop Auth) | 100 req/phút | Dành cho người dùng đã đăng nhập thao tác giỏ hàng, đặt hàng, profile. |

- **Khóa Trang Gốc (Giải Pháp 1 - Exact Regex `~^/$`)**: `route-spa-root` chỉ chấp nhận duy nhất `/` và `/index.html`.
- **Khóa Static Assets (Giải Pháp 2 - Root Bundle Regex)**: `route-spa-assets` chỉ mở `/assets`, `/vendor` và các bundle `.js`, `.css`, `.ico`, `.png`, `.svg`, `.woff2`, `.map` tại root.
- Mọi truy cập vào `/ftp/*`, `/encryptionkeys/*`, `/support/logs/*`, `/rest/admin/*` đều bị chặn 100%.

---

## 5. Kết Quả Kiểm Thử Thực Nghiệm

| Bộ Test Suite | Số Lượng Tests | Kết Quả | Nội Dung Xác Minh |
| :--- | :---: | :---: | :--- |
| **`tests/gateway/test_gateway_config.py`** | 7 | **100% PASS** | Kiểm tra cú pháp `allowlist.json`, xác minh trình sinh route động `${GENERATED_ROUTES_YAML}`, kiểm tra template, script Lua và Compose override. |
| **`tests/guardrails/` (Milestone 1)** | 16 | **100% PASS** | Khử khuẩn PII/Secret và phòng vệ Prompt Injection hoạt động chính xác. |
| **`tests/agent/` (Regression)** | 34 | **100% PASS** | Toàn bộ luồng phân tích và nạp prompt của AI Agent tương thích hoàn toàn. |
| **Toàn bộ Repository (`pytest tests/`)** | 331 | **100% PASS** | Đảm bảo tính toàn vẹn của tất cả các module. |
| **Kiểm tra Định dạng (`make quality`)** | Clean | **100% PASS** | Đạt chuẩn Ruff lint, Docker compose config và Contract scripts. |
