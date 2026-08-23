# Project Sentinel — Automated DevSecOps & ReAct AI Security Operations Platform

Project Sentinel là nền tảng DevSecOps tự động hóa toàn diện, cung cấp môi trường phân tích bảo mật có thể tái lập trên ứng dụng mục tiêu được cấp phép (OWASP Juice Shop `v20.1.1` & Vulnerable Mock Server). Hệ thống tích hợp quét mã nguồn tĩnh (SAST), quét lỗ hổng động (DAST), chuẩn hóa kết quả sang Unified Findings JSONL, truy hồi tri thức bảo mật đa phương thức (Hybrid Search FTS5 + Qdrant), và **ReAct Security Analysis Agent** với khả năng tự trị gọi công cụ kiểm chứng lỗ hổng qua **API Gateway**, bảo vệ bởi **Dual-Layer Guardrails** (khử khuẩn PII/Secrets, ngăn chặn Prompt Injection) và chốt chặn phê duyệt của con người (**Human-in-the-Loop**).

---

## 📑 Mục lục

- [Tổng quan Kiến trúc](#-tổng-quan-kiến-trúc)
- [Yêu cầu Hệ thống](#-yêu-cầu-hệ-thống)
- [Cài đặt & Khởi tạo Nhanh (Quickstart)](#-cài-đặt--khởi-tạo-nhanh-quickstart)
- [Cấu hình Biến Môi Trường (.env)](#-cấu-hình-biến-môi-trường-env)
- [Hướng dẫn Vận hành Full Luồng (End-to-End Workflow)](#-hướng-dẫn-vận-hành-full-luồng-end-to-end-workflow)
  - [Lựa chọn 1: Vận hành qua Giao diện Web (Streamlit Bento Dashboard)](#lựa-chọn-1-vận-hành-qua-giao-diện-web-streamlit-bento-dashboard)
  - [Lựa chọn 2: Vận hành qua Dòng lệnh CLI (Makefile Commands)](#lựa-chọn-2-vận-hành-qua-dòng-lệnh-cli-makefile-commands)
- [Kiểm thử & Đảm bảo Chất lượng](#-kiểm-thử--đảm-bảo-chất-lượng)
- [Gitleaks Git hooks](#gitleaks-git-hooks)
- [CI/CD GitHub Actions](#-cicd-github-actions)
- [Dọn dẹp Môi trường (Cleanup)](#-dọn-dẹp-môi-trường-cleanup)
- [Xử lý Sự cố Thường gặp (Troubleshooting)](#-xử-lý-sự-cố-thường-gặp-troubleshooting)

---

## 🏛️ Tổng quan Kiến trúc

```mermaid
flowchart TD
    subgraph TargetEnv ["1. Target Environment"]
        JuiceShop["OWASP Juice Shop (v20.1.1)"]
        MockServer["Vulnerable Mock Server (:3000)"]
    end

    subgraph Scanners ["2. Multi-Engine Scanners"]
        Semgrep["Semgrep SAST (NodeJS/JS)"]
        CodeQL["CodeQL SAST (Taint Analysis)"]
        ZAP["OWASP ZAP DAST (Baseline & Full)"]
        SQLMap["sqlmap DAST (Targeted SQLi)"]
    end

    subgraph Pipeline ["3. Normalization & Knowledge Base"]
        Normalizer["Unified Findings Normalizer"]
        UnifiedJSONL["Unified Findings JSONL"]
        KBEngine["Hybrid Knowledge Engine (SQLite FTS5 + Qdrant Vector)"]
    end

    subgraph ReActAgent ["4. ReAct AI Security Agent"]
        AgentCore["ReAct Reasoning Loop (Thought -> Action -> Observation)"]
        Correlator["SAST <-> DAST Correlator"]
        Tools["Tool Dispatcher (search_kb, lookup_payloads, send_safe_request)"]
    end

    subgraph SafeGateway ["5. Safe API Gateway & Guardrails"]
        KongGateway["Kong API Gateway (:3000)"]
        HITL["Human-in-the-Loop (120s Fail-Safe Queue)"]
        Guardrails["Dual-Layer Guardrails (PII Masking + Untrusted Response Wrap)"]
    end

    subgraph Output ["6. Deliverables & Interfaces"]
        ReportJSONL["Security Analysis Report JSONL"]
        WebUI["Bento Box Web Dashboard (:8501)"]
    end

    TargetEnv --> Scanners
    Scanners --> Normalizer --> UnifiedJSONL
    UnifiedJSONL & KBEngine --> AgentCore
    AgentCore --> Correlator
    AgentCore --> Tools
    Tools --> SafeGateway
    SafeGateway --> TargetEnv
    SafeGateway --> Guardrails --> AgentCore
    AgentCore --> ReportJSONL --> WebUI
```

---

## 💻 Yêu cầu Hệ thống

- **Hệ điều hành**: Linux x86_64, macOS (Docker Desktop), hoặc Windows WSL2 (Docker Desktop).
- **Công cụ cơ sở**: Git, GNU Make, Bash, Docker & Docker Compose v2, `curl`, `jq`.
- **Python**: Python 3.11 hoặc 3.12 (khuyến nghị dùng virtualenv `.venv`).
- **Gitleaks**: `v8.30.1+` (bảo vệ secret scanning qua pre-commit / pre-push hooks).

### ⚙️ Cấu hình phần cứng:
| Mức cấu hình | RAM | CPU Cores | Ổ cứng khả dụng | Khả năng đáp ứng |
| :--- | :--- | :--- | :--- | :--- |
| **Tối thiểu (Minimum)** | 8 GB (Cấp 6GB cho Docker) | 4 cores | 15 GB SSD | Web UI, Target App, Semgrep SAST, ZAP Baseline |
| **Khuyến nghị (Recommended)** | 16 GB (Cấp 12GB cho Docker) | 6 – 8 cores | 30 GB SSD | CodeQL Database Build, ZAP Full Scan Spider, ReAct Multi-turn Probing |

---

## 🚀 Cài đặt & Khởi tạo Nhanh (Quickstart)

Chỉ với 5 bước đơn giản để thiết lập toàn bộ môi trường từ đầu:

```bash
# 1. Kiểm tra môi trường host và Docker daemon
make doctor

# 2. Khởi tạo môi trường ảo Python & cài đặt dependencies
make install
source .venv/bin/activate

# 3. Tạo file cấu hình môi trường từ mẫu
cp .env.example .env
# Chỉnh sửa API Key hoặc Model trong file .env (xem mục Cấu hình bên dưới)

# 4. Tải và khởi tạo ứng dụng mục tiêu (OWASP Juice Shop)
make setup-target
make target-build

# 5. Xây dựng Kho Tri thức Bảo mật (SQLite FTS5 & Vector Store)
make kb-build
```

---

## ⚙️ Cấu hình Biến Môi Trường (.env)

Tập tin `.env` quản lý các API Key và cấu hình hoạt động:

```env
# 1. Cấu hình Ứng dụng Mục tiêu & Scanner
JUICE_SHOP_PORT=3000
SEMGREP_APP_TOKEN=your-semgrep-token-here

# 2. Cấu hình AI Security Analysis Agent (LLM)
LLM_API_KEY=your-llm-api-key-here
LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
LLM_MODEL=qwen-plus
LLM_TEMPERATURE=0.1
LLM_MAX_RETRIES=2

# 3. Cấu hình Embedding Provider (Truy hồi Ngữ nghĩa)
# Hỗ trợ: 'fastembed' (100% Offline ONNX - Mặc định), 'dashscope', 'openai', 'mock'
EMBEDDING_PROVIDER=fastembed
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
EMBEDDING_DIMENSION=384

# 4. Cấu hình API Gateway & Human-In-The-Loop
GATEWAY_HOST=http://localhost:3000
GATEWAY_AGENT_API_KEY=sentinel-agent-safe-key-prod-2026
HITL_TIMEOUT_SECONDS=120
```

---

## 🛡️ Hướng dẫn Vận hành Full Luồng (End-to-End Workflow)

Hệ thống hỗ trợ 2 phương thức vận hành song song và đồng bộ 100%:

---

### 📋 Xem Danh Sách Lệnh và Tham Số (Make Help)

Để xem toàn bộ danh mục các lệnh `make`, kèm giải thích chi tiết các tham số đầu vào và giá trị mặc định, hãy chạy:

```bash
make help
```

---

### Lựa chọn 1: Vận hành Full Luồng qua Giao diện Web (Streamlit Bento Dashboard)

Khởi động giao diện Web Dashboard Bento Box:
```bash
make ui-build    # Build container UI (chạy 1 lần đầu)
make ui          # Khởi động UI chạy nền tại http://localhost:8501
```

Truy cập **`http://localhost:8501`** trên trình duyệt để vận hành full luồng 6 bước:

#### 🔹 Bước 1: Quét Lỗ Hổng Bảo Mật (Tab 1 — Quét Bảo Mật)
1. Kiểm tra thẻ **Trạng Thái Ứng Dụng Mục Tiêu**: Đảm bảo hiển thị `Target Online (HTTP 200)`.
2. Chọn công cụ quét trong danh sách thả xuống:
   - **SAST**: `Semgrep SAST` hoặc `CodeQL SAST`.
   - **DAST**: `ZAP Baseline Scan` (User), `ZAP Full Scan`, `ZAP Admin Scan`, hoặc `sqlmap DAST`.
3. Bấm **Khởi Chạy Quét (Run Scanner)**: Theo dõi tiến trình quét và live log stream trực tiếp trên giao diện. File báo cáo thô sẽ được lưu tự động vào thư mục `reports/raw/` (ví dụ: `reports/raw/zap.json`).

#### 🔹 Bước 2: Quản Lý & Chuẩn Hóa Dữ Liệu (Tab 2 — Quản Lý Dữ Liệu)
1. Danh sách các file raw scanner report đã quét sẽ hiển thị tại bảng danh mục.
2. Tích chọn các tệp muốn đưa vào phân tích (ví dụ: tích chọn chỉ `zap.json` hoặc tích `Chọn tất cả các file raw`).
3. Bấm **Chuẩn Hóa Báo Cáo (Run Normalizer)**:
   - Hệ thống tiến hành mapping dữ liệu, loại bỏ trùng lặp và sinh tệp `reports/normalized/unified-findings-YYYYMMDDTHHMMSSZ.jsonl` tuân thủ 100% JSON Schema v2.0.0.
   - Kết quả tóm tắt quá trình chuẩn hóa (số lượng findings theo từng công cụ, fingerprint collisions) được hiển thị trực quan.

#### 🔹 Bước 3: Tra Cứu Tri Thức Bảo Mật (Tab 3 — Tra Cứu Tri Thức)
1. Nhập từ khóa hoặc mã định danh bảo mật tại ô tìm kiếm (Ví dụ: `CWE-89`, `SQL Injection`, hoặc `chống rò rỉ dữ liệu nhạy cảm`).
2. Lựa chọn chế độ tìm kiếm:
   - **Hybrid Search (Mặc định)**: Kết hợp RRF + MMR giữa FTS5 và Dense Vector (tối ưu nhất).
   - **Sparse BM25 Keyword**: Tìm kiếm chính xác từ khóa và mã định danh trên SQLite FTS5.
   - **Dense Vector Semantic**: Tìm kiếm theo ngữ nghĩa và bối cảnh tự nhiên.
3. Bấm **Tra Cứu Tri Thức**: Xem các Bento Card chứa nội dung chi tiết của tài liệu canonical, mã mẫu phòng thủ, và yêu cầu xác thực OWASP ASVS.

#### 🔹 Bước 4: Kiểm Thử An Toàn Qua Gateway (Tab 4 — Kiểm Thử Gateway)
1. Nhập endpoint cần kiểm thử vào ô `Endpoint` (Ví dụ: `/rest/products/search?q=apple` hoặc `/api/vulnerable/env-config`).
2. Chọn phương thức HTTP tuân thủ chính sách nghiêm ngặt (`GET`, `OPTIONS`, `PUT`).
3. Chọn nhóm payload mẫu an toàn từ danh mục `payloads.json` hoặc nhập custom payload / headers.
4. Bấm **Gửi Request Kiểm Thử (Send Safe Request)**:
   - Request được gửi qua Kong API Gateway với tự động tiêm `x-api-key`.
   - Nếu là request có rủi ro (phương thức `PUT` hoặc `Burst Rate Limit`), yêu cầu sẽ được chuyển vào **Hàng Đợi Phê Duyệt (HITL Queue)** ở Sidebar với đếm ngược 120s Fail-Safe.
   - Phản hồi nhận về được khử khuẩn 100% dữ liệu nhạy cảm (PII, Password, Token) và bọc trong thẻ XML `<untrusted_http_response>` bảo vệ chống Prompt Injection.

#### 🔹 Bước 5: Phân Tích & Báo Cáo AI Agent (Tab 5 — Báo Cáo & Phân Tích)
1. Chọn tệp `Unified Findings JSONL` đã chuẩn hóa ở Bước 2 tại mục danh sách đầu vào.
2. Cấu hình tham số tác nhân:
   - **Chế độ Agent**: Chọn `ReAct Agent (Tự động gọi Tool + Safe Probe)` (Mặc định).
   - **Mô hình LLM**: Chọn mô hình hoạt động (ví dụ: `my-combo`, `qwen-plus`, hoặc `ag/gemini-3-flash`).
   - **Số bước ReAct tối đa**: Đặt từ 3 – 5 bước suy luận.
3. Bấm **Khởi Chạy Phân Tích (Run Agent Analysis)**:
   - ReAct Agent tự động phân nhóm findings (`AnalysisGroup`), tra cứu tri thức bảo mật, gửi probe kiểm chứng qua Gateway và đối soát tương quan SAST <-> DAST.
   - Kết quả xuất ra file `reports/analyzed/security-analysis-report-YYYYMMDDTHHMMSSZ.jsonl` đảm bảo 100% Finding Coverage.
   - Giao diện hiển thị Executive KPI Grid, ma trận phân loại mối đe dọa và bảng phân tích chi tiết từng nhóm lỗ hổng.

#### 🔹 Bước 6: Giám Sát & Nhật Ký Kiểm Toán (Tab 6 — Giám Sát & Logs)
1. Theo dõi bảng **Live Gateway Network Audit Logs** (`logs/gateway-network-audit.jsonl`): Giám sát mọi request probe đã gửi, mã phản hồi HTTP, trạng thái duyệt HITL và độ trễ mạng.
2. Theo dõi **Agent Execution Logs** (`logs/agent-runner.log`): Giám sát chi tiết chu trình suy luận đa bước của ReAct Agent.

---

### Lựa chọn 2: Vận hành qua Dòng lệnh CLI (Makefile Commands)

Mọi tính năng trên giao diện UI đều có lệnh `make` tương ứng trực tiếp (chạy `make help` để xem hướng dẫn đầy đủ):

#### 1. Quét SAST & DAST (Tương đương Tab 1)

##### A. Quét SAST (Semgrep & CodeQL)
- **Semgrep SAST**: `make sast-semgrep` (quét rulesets NodeJS/JS với token `SEMGREP_APP_TOKEN`). Output: `reports/raw/semgrep.json`.
- **CodeQL SAST**: `make sast-codeql` (quét deep taint analysis, thêm 2 dòng ngữ cảnh mã nguồn bằng `--sarif-add-snippets`). Output: `reports/raw/codeql.sarif`.
- **Quét SAST liên hoàn**: `make sast`.

##### B. Quét DAST (OWASP ZAP & sqlmap)

### Chạy ZAP Baseline local (passive)
- **Lệnh**: `make dast` (User) hoặc `make dast-zap-admin` (Admin).
- **Automation Plans**: Đặt tại `configs/zap/` (`baseline.yaml` và `baseline-admin.yaml`).
- **Strict Scope Guardrail**: Cấu hình `scopeCheck: Strict` cho Client Spider để ngăn browser điều hướng ra bên ngoài target (ví dụ URI `https://github.com/juice-shop/juice-shop`).
- **Artifacts**: Xuất `reports/raw/zap.json`, `zap.meta.json`, `zap-endpoints.txt` (endpoint inventory) và `zap-site-tree.yaml` (ZAP site tree).

### Chạy ZAP Full Scan local (active)
- **Lệnh**: `make dast-zap-fullscan` (User) hoặc `make dast-zap-fullscan-admin` (Admin).
- **Automation Plans**: Đặt tại `configs/zap/` (`full.yaml` và `full-admin.yaml`).
- **Artifacts & Log**: Xuất `reports/raw/zap.json`, `zap.meta.json`, `zap-endpoints.txt`, `zap-site-tree.yaml` và log `logs/zap-fullscan-runner.log`.

##### C. sqlmap DAST (Targeted SQL Injection)
- **Lệnh**: `make dast-sqlmap` (kiểm thử tham số `q` tại `/rest/products/search`). Output: `reports/raw/sqlmap.json`.
- **Quét toàn bộ SAST & DAST liên hoàn**: `make sast && make dast`.

---

#### 2. Chuẩn hóa Scanner Reports sang Unified Findings (Tương đương Tab 2)
```bash
# Xác thực tính hợp lệ của các file raw reports trong reports/raw/
make validate-reports

# Chuẩn hóa toàn bộ sang reports/normalized/unified-findings-YYYYMMDDTHHMMSSZ.jsonl
make normalize
```
*Lưu ý: Normalizer chỉ giữ lại các finding có origin trùng khớp chính xác với target scope. Số instance ngoài scope bị loại bỏ được ghi nhận tại `out_of_scope_instances_filtered` trong normalization summary.*

---

#### 3. Tra cứu Tri thức Bảo mật (Tương đương Tab 3)
```bash
# Tìm kiếm Hybrid (RRF + MMR - Mặc định)
make kb-search QUERY="SQL Injection" TOP_K=5

# Tìm kiếm Từ khóa FTS5 BM25 (Hỗ trợ mã định danh và từ khóa tiếng Việt)
make kb-search-keyword QUERY="CWE-89"
make kb-search-keyword QUERY="XSS và CSRF"

# Tìm kiếm Ngữ nghĩa Vector
make kb-search-semantic QUERY="bypassing authentication via missing jwt validation"

# Tra cứu chi tiết toàn văn 1 tài liệu theo mã
make kb-inspect DOC_ID=cwe-89

# Xem thống kê số lượng tài liệu theo danh mục
make kb-stats
```

---

#### 4. Kiểm thử An toàn qua API Gateway (Tương đương Tab 4)
```bash
# Khởi động Kong Gateway và Target App cùng lúc (:3000)
make gateway-up

# Gửi request thăm dò an toàn (GET - rủi ro thấp)
make test-request ARGS="--url /rest/products/search?q=apple"

# Kiểm tra CORS & Phương thức cho phép (OPTIONS)
make test-request ARGS="--url /api/Products --method OPTIONS"

# Gửi request PUT (Kích hoạt chốt chặn phê duyệt HITL 120s)
make test-request ARGS="--url /rest/products/1/reviews --method PUT --payload-category special_chars"

# Kiểm tra Gateway chặn Rate Limit (Burst 25 requests -> HTTP 429)
make test-request ARGS="--url /api/Products --method GET --count 25"

# Kiểm tra Gateway chặn Payload ngoại cỡ (1.5MB Buffer -> HTTP 413)
make test-request ARGS="--url /api/Products --method GET --oversized"
```

---

#### 5. Phân tích Chuyên sâu với ReAct AI Agent (Tương đương Tab 5)
```bash
# 1. Chạy ReAct Agent (MẶC ĐỊNH - Tự động gọi Tool tra cứu KB và Probe Gateway):
make agent-analyze FINDINGS=reports/normalized/unified-findings-20260822T000000Z.jsonl

# 2. Tùy chỉnh số bước suy luận tối đa và Model LLM:
make agent-analyze FINDINGS=reports/normalized/unified-findings-20260822T000000Z.jsonl MODE=react MAX_STEPS=5 MODEL=qwen-plus

# 3. Chạy chế độ Static 1-Pass RAG (Baseline đối soát benchmark):
make agent-analyze FINDINGS=reports/normalized/unified-findings-20260822T000000Z.jsonl MODE=static
```

---

#### 6. Chạy Demo Tự Động 4 Giai Đoạn (Live Mock Probe Demo)
```bash
# Chạy kịch bản thực nghiệm đối soát Guardrails và ReAct Agent với Vulnerable Mock Server
make test-live-mock-probe
```

---

## 🧪 Kiểm thử & Đảm bảo Chất lượng

Chạy toàn bộ các bộ kiểm thử tự động của dự án:

```bash
make quality              # Kiểm tra toàn diện: Ruff linter, shell syntax, compose config và schema contracts
make test                 # Chạy unit & integration tests cho normalizers và platform (125 tests)
make kb-test              # Chạy tests cho Knowledge Base, SQLite FTS5, FastEmbed và Hybrid Search (137 tests)
make gateway-test         # Chạy tests cho Kong Gateway, Safe Requester, HITL và Audit Logger (37 tests)
make agent-test           # Chạy test suite cho ReAct Security Analysis Agent & Tools (73 tests)
make test-mock-guardrails # Chạy test thực nghiệm bảo vệ Guardrails trên Vulnerable Mock Server
```

---

## Gitleaks Git hooks

Repository cung cấp hai native Git hooks để quét secret:
- `.githooks/pre-commit`: Quét chính xác nội dung đang được stage;
- `.githooks/pre-push`: Quét các commit sắp được đẩy lên remote. Với branch hoặc tag mới, hook quét toàn bộ lịch sử có thể truy cập từ ref đó.

Hooks yêu cầu Gitleaks `v8.30.1` trở lên. Kiểm tra phiên bản đang có:
```bash
gitleaks version
```

### Kích hoạt hooks:
```bash
git config --local core.hooksPath .githooks
```

Quét toàn bộ lịch sử trước lần push đầu tiên:
```bash
gitleaks git --redact --verbose .
```

---

## 🔄 CI/CD GitHub Actions

Workflow chính chạy `quality`, sau đó khởi chạy SAST và ZAP Baseline DAST song song trên GitHub Actions.
Mỗi workflow run xuất bản các artifacts:
- `semgrep-raw-<run_id>`
- `codeql-raw-<run_id>`
- `zap-raw-<run_id>`
- `zap-fullscan-raw-<run_id>`
- `normalized-findings-<run_id>`
- `dast-logs-<run_id>`

---

## 🧹 Dọn dẹp Môi trường (Cleanup)

```bash
# Xóa các báo cáo tạm trong reports/raw/ và reports/normalized/
make clean-reports

# Dừng Kong Gateway và Juice Shop target
make gateway-down

# Dừng riêng Web UI Dashboard
make ui-down

# Dừng toàn bộ containers và mạng Docker của Sentinel
make down

# Xóa container, Docker volumes và thư mục target clone
make clean
```

---

## ❓ Xử lý Sự cố Thường gặp (Troubleshooting)

| Vấn đề | Nguyên nhân | Cách khắc phục |
| :--- | :--- | :--- |
| **Port 3000 bị chiếm dụng** | Ứng dụng khác đang chạy trên port 3000 | Đổi `JUICE_SHOP_PORT=3001` trong `.env`, sau đó chạy `make target-up` hoặc `make gateway-up`. |
| **`ModuleNotFoundError: No module named '_sqlite3'`** | Python thiếu header SQLite khi biên dịch | Chạy `make install` để hệ thống tự kiểm tra và cấu hình môi trường ảo Python có sẵn SQLite FTS5. |
| **Lệch số chiều Vector (`shapes not aligned`)** | Dimension giữa model và Qdrant collection không khớp | Kiểm tra `EMBEDDING_PROVIDER` trong `.env` (`384` cho FastEmbed, `1024` cho DashScope, `1536` cho OpenAI) rồi chạy `make kb-rebuild`. |
| **Semgrep báo thiếu token** | Chưa cấu hình token xác thực | Thêm `SEMGREP_APP_TOKEN` hợp lệ vào `.env` trước khi chạy `make sast-semgrep`. |
| **CodeQL báo `out of Java heap`** | Docker Daemon thiếu RAM | Tăng bộ nhớ Docker Engine/Desktop lên ít nhất 4 GB (khuyến nghị 8–12 GB). |
| **HITL Request bị Timeout sau 120s** | Không có tương tác Approve/Reject kịp thời | Đây là cơ chế Fail-Safe mặc định (tự động từ chối request rủi ro). Bấm gửi lại hoặc thêm flag `--auto-approve` khi chạy CI tự động. |
