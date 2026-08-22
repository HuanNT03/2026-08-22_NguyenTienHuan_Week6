# Báo Cáo Kỹ Thuật Tuần 5: Kiến Trúc Kong API Gateway Client-First & Cơ Chế Tự Động Hóa Allowlist

## 1. Tổng Quan Mục Tiêu & Kiến Trúc Bảo Mật

Trong khuôn khổ **Project Sentinel**, việc đưa **Kong API Gateway (`kong:3.6.1`)** đứng trước ứng dụng mục tiêu **OWASP Juice Shop (`v20.1.1`)** nhằm thực hiện 3 trụ cột an ninh:
1. **Nguồn chân lý duy nhất (Single Source of Truth)**: Toàn bộ danh mục route, phân quyền truy cập và hạn ngạch tốc độ được quản lý tập trung tại `src/gateway/allowlist.json`. Khi cần bổ sung endpoint mới, kỹ sư chỉ cần cập nhật một tệp JSON duy nhất mà không cần can thiệp vào tệp cấu hình Gateway.
2. **Phân quyền Client-First (Consumer-Scoped Authorization & Rate Limiting)**: Nhận diện và áp dụng chính sách giới hạn tốc độ riêng biệt ở cấp độ danh tính Client (Consumer) cho 3 nhóm đối tượng: AI Security Agent (`ai-agent`: 20 req/min), Khách vãng lai (`anonymous-user`: 60 req/min) và Người dùng đăng nhập (`juice-shop-users`: 100 req/min).
3. **Triệt tiêu lỗ hổng Fallback Wildcard `/`**: Ngăn chặn kẻ tấn công lợi dụng route gốc Single Page Application (SPA) để bypass Allowlist và truy cập trái phép vào các endpoint nhạy cảm (`/ftp`, `/encryptionkeys`, `/support/logs`, `/rest/admin/*`).

---

## 2. Sơ Đồ Kiến Trúc Biên Dịch Boot-Time & Luồng Xử Lý Request

```mermaid
flowchart TD
    subgraph SingleSourceOfTruth [1. Single Source of Truth & Environment]
        AllowlistJSON["src/gateway/allowlist.json<br/>(15 Routes, 3 Clients Matrix)"]
        TemplateYML["src/gateway/kong.yml.template<br/>(Chứa Placeholders & Consumer Plugins)"]
        EnvKey["Biến Môi Trường .env<br/>KONG_VAULT_ENV_AGENT_API_KEY"]
    end

    subgraph BootTimeCompilation [2. Bộ Biên Dịch Boot-Time LuaJIT]
        LuaCompiler["src/gateway/render_config.lua<br/>(Khởi chạy trước khi Kong Daemon start)"]
        GenRoutes["Tự động sinh khối Routes tối giản<br/>${GENERATED_ROUTES_YAML}"]
        GenAgentLUT["Tự động sinh bảng tra cứu Agent O(1)<br/>${ALLOWED_PATHS_LUA}"]
        InjectKey["Nạp API Key vào Consumer ai-agent<br/>${AGENT_API_KEY}"]
        OutputYML["Xuất tệp hoàn chỉnh: /tmp/kong.yml"]
    end

    subgraph KongRuntimeEngine [3. Kong Gateway Engine (DB-less Mode)]
        KongLoad["Kong nạp /tmp/kong.yml vào RAM"]
        
        Req[HTTP Request tới Gateway :3000] --> PreFunc{Lua Pre-Function Check}
        
        PreFunc -->|Có x-api-key| CheckAgent{Key Hợp Lệ & Path thuộc Agent LUT?}
        CheckAgent -->|Không hợp lệ / Không thuộc allowlist| BlockAgent[401 Unauthorized / 403 Forbidden]
        CheckAgent -->|Hợp lệ| ConsumerAgent[Consumer: ai-agent]
        ConsumerAgent --> RateAgent["Consumer Rate Limit:<br/>20 req/phút"]
        
        PreFunc -->|Không có x-api-key| MatchRoute{Khớp Route trong YAML?}
        MatchRoute -->|Không khớp: /ftp, /metrics, /encryptionkeys| BlockPublic[404 Not Found / 403 Forbidden]
        MatchRoute -->|Khớp Route| KeyAuth{Key-Auth Plugin}
        KeyAuth -->|Khách vãng lai| ConsumerGuest[Consumer: anonymous-user]
        KeyAuth -->|User có Token| ConsumerUser[Consumer: juice-shop-users]
        
        ConsumerGuest --> RateGuest["Consumer Rate Limit:<br/>60 req/phút"]
        ConsumerUser --> RateUser["Consumer Rate Limit:<br/>100 req/phút"]
        
        RateAgent --> ProxyTarget[Forward vào Juice Shop :3000]
        RateGuest --> ProxyTarget
        RateUser --> ProxyTarget
        
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

### 3.1. Cơ chế Tạo Route Tự Động Tối Giản (`${GENERATED_ROUTES_YAML}`)
- Script `render_config.lua` phân tích mảng `routes` trong `src/gateway/allowlist.json`.
- Với mỗi route, script tự động sinh cấu trúc YAML chuẩn sạch cho Kong Gateway:
  ```yaml
        - name: route-products-browse
          paths:
            - /api/Products
            - /rest/products/search
          methods:
            - GET
          strip_path: false
  ```
- **Tối ưu hóa**: Toàn bộ định nghĩa Route không cần chứa khối `plugins: [rate-limiting]` lặp đi lặp lại. Cấu hình Route trở nên trong sáng, ngắn gọn và tập trung thuần túy vào việc định tuyến URL.

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

### 3.3. Cơ chế Giới Hạn Tốc Độ Chuẩn Client-First (Consumer-Scoped Rate Limiting)

Hệ thống quản lý Rate Limiting tập trung 100% ở **cấp độ Consumer (Client Identity)** tại `kong.yml.template`:

```yaml
plugins:
  # 1. AI Security Agent: 20 requests per minute
  - name: rate-limiting
    consumer: ai-agent
    config:
      minute: 20
      policy: local

  # 2. Khách vãng lai (Guest / Anonymous): 60 requests per minute
  - name: rate-limiting
    consumer: anonymous-user
    config:
      minute: 60
      policy: local

  # 3. Người dùng đăng nhập (Authenticated Users): 100 requests per minute
  - name: rate-limiting
    consumer: juice-shop-users
    config:
      minute: 100
      policy: local
```

- **Nguyên lý vận hành**: Khi bất kỳ Client nào gửi request, Kong nhận diện danh tính thông qua `key-auth` và tự động áp dụng chính xác hạn ngạch của Client đó trên toàn bộ các route mà không cần cấu hình phân tán ở từng API.

---

## 4. Ma Trận Cấu Hình Client-First & Cơ Chế Khóa Fallback

| Nhóm Client | Consumer Định Danh | Phương Thức Xác Thực | Nhóm ACL | Rate Limit (Toàn Hệ Thống) | Mục Đích Sử Dụng |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **`agent`** | `ai-agent` | `key-auth` (`x-api-key`) | `agent-group` | **20 req/phút** | Dành riêng cho AI Security Agent thăm dò các điểm nghi vấn. |
| **`guest`** | `anonymous-user` | `anonymous` (Key-Auth Fallback) | `guest-group` | **60 req/phút** | Dành cho người dùng công khai duyệt sản phẩm, đăng ký tài khoản. |
| **`user`** | `juice-shop-users` | `jwt` (Native Juice Shop Auth) | `user-group` | **100 req/phút** | Dành cho người dùng đã đăng nhập thao tác giỏ hàng, đặt hàng, profile. |

- **Khóa Trang Gốc (Giải Pháp 1 - Exact Regex `~^/$`)**: `route-spa-root` chỉ chấp nhận duy nhất `/` và `/index.html`.
- **Khóa Static Assets (Giải Pháp 2 - Root Bundle Regex)**: `route-spa-assets` chỉ mở `/assets`, `/vendor` và các bundle `.js`, `.css`, `.ico`, `.png`, `.svg`, `.woff2`, `.map` tại root.
- Mọi truy cập vào `/ftp/*`, `/encryptionkeys/*`, `/support/logs/*`, `/rest/admin/*` đều bị chặn 100%.

---

## 5. Kết Quả Kiểm Thử Thực Nghiệm

| Bộ Test Suite | Số Lượng Tests | Kết Quả | Nội Dung Xác Minh |
| :--- | :---: | :---: | :--- |
| **`tests/gateway/test_gateway_config.py`** | 7 | **100% PASS** | Kiểm tra cú pháp `allowlist.json`, xác minh trình sinh route động `${GENERATED_ROUTES_YAML}`, kiểm tra template, consumer plugins, script Lua và Compose override. |
| **`tests/guardrails/` (Milestone 1)** | 16 | **100% PASS** | Khử khuẩn PII/Secret và phòng vệ Prompt Injection hoạt động chính xác. |
| **`tests/agent/` (Regression)** | 34 | **100% PASS** | Toàn bộ luồng phân tích và nạp prompt của AI Agent tương thích hoàn toàn. |
| **Toàn bộ Repository (`pytest tests/`)** | 331 | **100% PASS** | Đảm bảo tính toàn vẹn của tất cả các module. |
| **Kiểm tra Định dạng (`make quality`)** | Clean | **100% PASS** | Đạt chuẩn Ruff lint, Docker compose config và Contract scripts. |
