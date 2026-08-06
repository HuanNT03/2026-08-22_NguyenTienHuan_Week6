# Project Sentinel — Week 2

Môi trường DevSecOps có thể tái lập để chạy OWASP Juice Shop `v20.1.1`, quét mã nguồn
bằng Semgrep cùng CodeQL, quét web thụ động bằng OWASP ZAP Baseline và chạy ZAP Full Scan
chủ động theo yêu cầu. Repository cũng có sqlmap local, được giới hạn vào một tham số search của
Juice Shop đã pin để phát hiện SQL injection và fingerprint DBMS. Source Juice Shop, generated raw
reports và runtime logs không được commit vào repository Sentinel.

## Mục lục

- [Phạm vi](#phạm-vi)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Quickstart](#quickstart)
- [Các lệnh Make](#các-lệnh-make)
- [SAST và DAST](#sast-và-dast)
- [Tìm kiếm tài liệu bảo mật bằng từ khóa](#tìm-kiếm-tài-liệu-bảo-mật-bằng-từ-khóa)
- [Gitleaks Git hooks](#gitleaks-git-hooks)
- [GitHub Actions](#github-actions)
- [Cleanup](#cleanup)
- [Troubleshooting](#troubleshooting)

## Phạm vi

Week 1 triển khai target pinning, Docker lifecycle, Semgrep/CodeQL SAST, ZAP Baseline DAST,
raw report validation và CI artifacts. Week 2 bổ sung unified findings normalizer cho Semgrep,
ZAP và CodeQL, cùng Security Knowledge Base hỗ trợ keyword search bằng SQLite FTS5. Semantic
Search, RAG, AI Agent, Gateway, guardrails, ground-truth evaluation và correlation nâng cao được
dành cho các task sau.

## Yêu cầu hệ thống

- Linux x86_64, macOS với Docker Desktop, hoặc Windows WSL2 với Docker Desktop;
- Git, Bash, GNU Make, Docker Engine/Desktop, Docker Compose v2;
- `curl` và `jq`;
- ít nhất 4 GiB memory cho Docker Engine/Desktop khi chạy CodeQL hoặc ZAP Client Spider.

Gitleaks `v8.30.1` trở lên được khuyến nghị để chạy secret-scanning Git hooks.

Không cần cài Node.js, Semgrep, CodeQL hoặc ZAP trên host. Chạy `make doctor` để kiểm tra môi trường.

## Quickstart

```bash
make doctor
make install
. .venv/bin/activate
cp .env.example .env
# Thay SEMGREP_APP_TOKEN placeholder trong .env bằng token thật.
make setup-target
make build
make up
make wait
make smoke
make sast
make dast
make validate-reports
make normalize
make down
```

`make install` chuẩn bị project virtualenv để `lint`, test và normalizer dùng đủ dependency.
`make sast` chạy Semgrep rồi CodeQL theo thứ tự. Có thể chạy riêng từng scanner khi cần:

```bash
make sast-semgrep
make sast-codeql
```

### Chạy ZAP Baseline local (passive)

Baseline thực hiện spider và passive scan, không chạy active scan. Chạy lifecycle riêng sau:

```bash
make setup-target
make build
make up
make wait
make smoke
make dast
make down
```

Kết quả gồm `reports/raw/zap.json`, metadata `reports/raw/zap.meta.json` có
`scan_profile=baseline`, inventory `reports/raw/zap-endpoints.txt` và site tree
`reports/raw/zap-site-tree.yaml`. Nếu một bước lỗi trước cleanup, vẫn chạy `make down`.

### Chạy ZAP Full Scan local (active)

Full Scan chạy spider, Client Spider và active scan có gửi payload kiểm thử. Chỉ chạy lifecycle
này trên Juice Shop đã pin của repository:

```bash
make setup-target
make build
make up
make wait
make smoke
make dast-zap-fullscan
make down
```

Ngoài bốn artifact ZAP giống Baseline và metadata có `scan_profile=full`, log chẩn đoán được
ghi tại `logs/zap-fullscan-runner.log` và `logs/zap-fullscan-zap.out`.

Baseline và Full Scan dùng chung `reports/raw/zap.json`; profile chạy sau ghi đè kết quả profile
trước. Hãy sao chép hoặc upload report trước khi chuyển profile nếu cần giữ cả hai. Không chạy hai
profile đồng thời. Với cả hai lifecycle, nếu một bước lỗi trước cleanup thì vẫn chạy `make down`.

### Chạy sqlmap local (bounded active scan)

sqlmap là active DAST: Juice Shop phải đang chạy trước khi scan. Runner không nhận URL hoặc cờ
từ người dùng; nó chỉ gửi request tới `GET /rest/products/search` với tham số `q` trong Docker
network `sentinel-security`.

```bash
make setup-target
make build
make up
make wait
make smoke
make dast-sqlmap
make down
```

Lệnh tự build image local `sentinel/sqlmap:1.10.7` từ package sqlmap đã pin hash. Nó chỉ dùng
`level=1`, `risk=1`, các technique boolean/error/union và DBMS fingerprinting; không crawl, không
đọc request/proxy log, không enumerate database/table, dump dữ liệu, chạy SQL tùy ý, đọc/ghi file
hoặc OS takeover. Kết quả ghi đè tại `reports/raw/sqlmap.json`; log chẩn đoán tại
`logs/sqlmap-runner.log`. Session sqlmap chỉ ở `/tmp` trong container và bị xóa khi container kết
thúc.

sqlmap report và log là scanner output không đáng tin cậy, có thể chứa payload hoặc response; không
đưa trực tiếp vào prompt/Agent. V1 này không tạo metadata sidecar, không được `make validate-reports`
kiểm tra, và chưa đi vào Unified Findings/CI.

Hoặc chạy toàn bộ luồng với cleanup runtime tự động:

```bash
make week1
```

Thứ tự của `week1` là `doctor → quality → setup-target → sast → build → up → wait →
smoke → dast → validate-reports → down`. Bước SAST chạy Semgrep rồi CodeQL trước khi build
runtime vì hai scanner chỉ cần source code.

Port host mặc định là `127.0.0.1:3000`. File `.env` dùng để cấu hình
`JUICE_SHOP_PORT` và token Semgrep local; file này đã được ignore và không được commit.
Container vẫn lắng nghe port `3000` trên network `sentinel-security`.

## Các lệnh Make

Chạy `make help` để xem danh sách đầy đủ. Các nhóm lệnh chính:

| Nhóm | Lệnh |
| --- | --- |
| Môi trường | `doctor`, `lint`, `test`, `quality` |
| Target | `setup-target`, `verify-target` |
| Runtime | `build`, `up`, `wait`, `smoke`, `status`, `logs`, `down` |
| Scanner | `sast`, `sast-semgrep`, `sast-codeql`, `dast`, `dast-zap-fullscan`, `dast-zap-admin`, `dast-zap-fullscan-admin`, `dast-sqlmap`, `validate-reports` |
| Normalization | `normalize` |
| Knowledge Base | `kb-validate`, `kb-build-documents`, `kb-build-index`, `kb-build`, `kb-rebuild` |
| Knowledge Search | `kb-search`, `kb-inspect`, `kb-stats`, `kb-test`, `kb-lint` |
| Orchestration | `week1` |
| Cleanup | `kb-clean`, `clean-reports`, `clean` |

`wait` polling HTTP cho đến khi ứng dụng thực sự ready. `smoke` là kiểm tra riêng từ host,
yêu cầu HTTP 2xx/3xx và response body không rỗng. `lint` chạy full Ruff trên `src/`, `tests/`
và Python scripts, sau đó kiểm tra Bash syntax cùng Docker Compose configuration.

## SAST và DAST

Sentinel sử dụng các công cụ SAST và DAST được cấu hình và giới hạn scope chặt chẽ:

### 1. Semgrep SAST
- **Lệnh**: `make sast-semgrep` (chạy riêng) hoặc `make sast` (chạy Semgrep rồi CodeQL).
- **Cấu hình**: Image `semgrep/semgrep:1.171.0`, rulesets `p/owasp-top-ten`, `p/javascript`, `p/nodejs`, `p/expressjs`.
- **Scope**: Cho phép theo `configs/semgrep/includes.txt` và loại trừ theo `configs/semgrep/.semgrepignore`. Loại bỏ `node_modules/`, test, CI và static codefixes.
- **Yêu cầu**: Biến môi trường `SEMGREP_APP_TOKEN` (export trong shell hoặc đặt trong `.env`). Output: `reports/raw/semgrep.json`.

### 2. CodeQL SAST
- **Lệnh**: `make sast-codeql`.
- **Image & Build**: Build từ `ubuntu:24.04` và CodeQL bundle dựa trên `CODEQL_VERSION` trong `configs/tool-versions.env`.
- **Phân tích & Snippets**: Chạy suite `javascript-security-extended.qls`. Truyền `--sarif-add-snippets` để đưa 2 dòng ngữ cảnh mã nguồn vào raw SARIF.
- **Output**: `reports/raw/codeql.sarif`. Database tạm trong container tự xóa sau khi hoàn tất.

### 3. OWASP ZAP DAST (Baseline & Full Scan)
- **Image & Target**: Image `ghcr.io/zaproxy/zaproxy:2.17.0`, quét target cố định `http://juice-shop:3000` trong network `sentinel-security`.
- **Lệnh Quét & Authentication**:
  - Mặc định (`make dast` / `make dast-zap-fullscan`): Quét Authenticated bằng tài khoản User (`user@juice-sh.op`).
  - Quét riêng Admin (`make dast-zap-admin` / `make dast-zap-fullscan-admin`): Quét Authenticated bằng tài khoản Admin (`admin@juice-sh.op`).
- **Automation Plans**: Đặt tại `configs/zap/` (`baseline.yaml`, `full.yaml` cho User; `baseline-admin.yaml`, `full-admin.yaml` cho Admin).
- **Strict Scope Guardrail**: Đặt `scopeCheck: Strict` cho Client Spider để ngăn browser điều hướng ra bên ngoài target (ví dụ URI `https://github.com/juice-shop/juice-shop`).
- **Artifacts**: Xuất 4 file: `zap.json`, `zap.meta.json`, `zap-endpoints.txt` (endpoint inventory) và `zap-site-tree.yaml` (ZAP site tree). Log Full Scan ghi tại `logs/zap-fullscan-runner.log`.

### 4. sqlmap DAST (Bounded Active Scan)
- **Lệnh**: `make dast-sqlmap`.
- **Scope**: Chỉ kiểm thử tham số `q` tại `GET /rest/products/search?q=apple` bằng image `sentinel/sqlmap:1.10.7`.
- **Output**: `reports/raw/sqlmap.json` và log `logs/sqlmap-runner.log`.

## Unified findings normalization

Lệnh `make normalize` chuẩn hóa các raw report từ scanner thành định dạng thống nhất tại `reports/normalized/unified-findings-YYYYMMDDTHHMMSSZ.jsonl` và `normalization-summary.json`.

### Các cặp Report & Metadata bắt buộc (`reports/raw/`)
| Scanner | Raw Finding Report | Sidecar Metadata |
| --- | --- | --- |
| Semgrep | `semgrep.json` | `semgrep.meta.json` |
| ZAP | `zap.json` | `zap.meta.json` |
| CodeQL | `codeql.sarif` | `codeql.meta.json` |

*(Lưu ý: `sqlmap.json` là raw report local v1 độc lập, không đưa vào normalizer).*

### Quy tắc xử lý
- **Lọc Out-of-Scope**: ZAP normalizer chỉ giữ lại các finding có HTTP origin trùng khớp chính xác với `target.base_url`. Số instance ngoài scope bị bỏ được ghi vào `out_of_scope_instances_filtered` trong summary.
- **Validation & Partial Failure**: `make validate-reports` kiểm tra các file rỗng/thiếu/malformed trước khi scan. Khi normalize, nếu thiếu input scanner sẽ có status `skipped` (`missing_input`), scanner hỏng có status `failed`. Chỉ cần ít nhất 1 cặp scanner hợp lệ, output normalized vẫn được tạo.
- **Thực thi**: Kích hoạt môi trường `.venv`, chạy `make validate-reports` rồi `make normalize`.

## Tìm kiếm tài liệu bảo mật bằng từ khóa

Cài dependency và build Knowledge Base trước lần tìm kiếm đầu tiên:

```bash
make install
make kb-validate
make kb-build
```

Tìm tài liệu bằng từ khóa hoặc security identifier qua Make:

```bash
make kb-search QUERY="SQL Injection"
make kb-search QUERY="SQLi"
make kb-search QUERY="XSS" TOP_K=5
make kb-search QUERY="CWE89"
make kb-search QUERY="Broken Access Control"
```

`TOP_K` mặc định là `5` và nhận giá trị từ `1` đến `50`. Có thể giới hạn kết quả theo
`doc_type`:

```bash
make kb-search QUERY="IDOR" DOC_TYPE=cwe
make kb-search QUERY="SQL Injection" DOC_TYPE=vulnerability_example
```

Các giá trị `DOC_TYPE` hợp lệ gồm:

- `owasp_category`;
- `cwe`;
- `scanner_document`;
- `scanner_rule`;
- `vulnerability_example`.

Để tích hợp với script hoặc Agent, gọi CLI trực tiếp với output JSON:

```bash
.venv/bin/python -m src.retrieval.cli search "CWE89" --json
.venv/bin/python -m src.retrieval.cli search "XSS" --top-k 10 --doc-type cwe --json
```

Query được chuẩn hóa tự động, vì vậy `CWE89`, `cwe 89`, `cwe_89` và `CWE-89` có cùng ý nghĩa;
`A01-2025`, `a01 2025`, `a1:2025` và `A01:2025` cũng tương đương. Các token được quote trước
khi truyền vào SQLite FTS5, nên toán tử hoặc ký tự đặc biệt trong input không điều khiển cú pháp
`MATCH`.

Xem đầy đủ một tài liệu canonical hoặc thống kê dataset/index:

```bash
make kb-inspect DOC_ID=cwe-89
make kb-stats
```

Nếu `knowledge-base/index/knowledge.db` chưa tồn tại hoặc canonical data đã thay đổi, chạy lại:

```bash
make kb-rebuild
```

Python code không cần gọi CLI bằng subprocess; dùng trực tiếp `KnowledgeSearchService` theo hướng
dẫn trong [`knowledge-base/README.md`](knowledge-base/README.md).

## Gitleaks Git hooks

Repository cung cấp hai native Git hooks:

- `.githooks/pre-commit` quét chính xác nội dung đang được stage;
- `.githooks/pre-push` quét các commit sắp được đẩy lên remote. Với branch hoặc tag mới,
  hook quét toàn bộ lịch sử có thể truy cập từ ref đó.

Hooks yêu cầu Gitleaks `v8.30.1` trở lên. Kiểm tra phiên bản đang có:

```bash
gitleaks version
```

Nếu chưa có Gitleaks hoặc phiên bản thấp hơn yêu cầu, hook in cảnh báo nhưng vẫn cho phép
commit/push. Khi phiên bản hợp lệ, finding hoặc lỗi trong quá trình scan sẽ chặn thao tác.

### Cài Gitleaks trên Linux

Ví dụ sau cài binary chính thức cho Linux x86_64 hoặc ARM64 vào `~/.local/bin` mà không cần
quyền root:

```bash
GITLEAKS_VERSION=8.30.1
case "$(uname -m)" in
  x86_64) GITLEAKS_ARCH=x64 ;;
  aarch64 | arm64) GITLEAKS_ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

GITLEAKS_ASSET="gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz"
GITLEAKS_BASE_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"

curl --fail --location --remote-name "$GITLEAKS_BASE_URL/$GITLEAKS_ASSET"
curl --fail --location --remote-name \
  "$GITLEAKS_BASE_URL/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
grep " $GITLEAKS_ASSET$" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" | sha256sum --check

tar -xzf "$GITLEAKS_ASSET" gitleaks
mkdir -p "$HOME/.local/bin"
install -m 0755 gitleaks "$HOME/.local/bin/gitleaks"
```

Bảo đảm `~/.local/bin` thuộc `PATH`, mở terminal mới rồi chạy `gitleaks version`. Nếu làm việc
trong WSL2, hãy chạy toàn bộ bước Linux bên trong distribution WSL đang chứa repository.

### Cài Gitleaks trên macOS

Cài bằng Homebrew rồi kiểm tra phiên bản:

```bash
brew install gitleaks
gitleaks version
```

Nếu đã cài nhưng thấp hơn phiên bản yêu cầu:

```bash
brew update
brew upgrade gitleaks
```

### Cài Gitleaks trên Windows

Với Git for Windows native, mở PowerShell và tải binary chính thức phù hợp với x64 hoặc ARM64:

```powershell
$Version = "8.30.1"
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
$Asset = "gitleaks_${Version}_windows_${Arch}.zip"
$BaseUrl = "https://github.com/gitleaks/gitleaks/releases/download/v${Version}"

Invoke-WebRequest "$BaseUrl/$Asset" -OutFile $Asset
Invoke-WebRequest "$BaseUrl/gitleaks_${Version}_checksums.txt" `
  -OutFile "gitleaks_${Version}_checksums.txt"

$Expected = ((Select-String -Path "gitleaks_${Version}_checksums.txt" `
  -Pattern " $([regex]::Escape($Asset))$").Line -split '\s+')[0].ToLowerInvariant()
$Actual = (Get-FileHash $Asset -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) { throw "Gitleaks checksum mismatch" }

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\Gitleaks"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Expand-Archive -Path $Asset -DestinationPath $InstallDir -Force
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($UserPath -split ';') -notcontains $InstallDir) {
  [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
}
```

Mở lại PowerShell và Git Bash, sau đó xác nhận `gitleaks version` hoạt động trong cả hai.
Nếu repository nằm trong WSL2, cài theo hướng dẫn Linux thay vì cài binary Windows.

Các gói và checksum chính thức nằm trên trang
[Gitleaks releases](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1).

### Kích hoạt hooks

Git không tự kích hoạt tracked hooks sau khi clone. Trước tiên, kiểm tra repository có dùng
hook path khác hay không:

```bash
git config --local --get core.hooksPath
```

Nếu lệnh không trả về giá trị, kích hoạt hooks của Sentinel:

```bash
git config --local core.hooksPath .githooks
git config --local --get core.hooksPath
```

Nếu đã có giá trị, không ghi đè ngay: `core.hooksPath` chỉ nhận một thư mục, vì vậy cần hợp nhất
các hook hiện hữu với `.githooks/` trước. Cấu hình này là local và mỗi clone phải thực hiện lại.

Trước lần push đầu tiên, quét toàn bộ lịch sử hiện tại:

```bash
gitleaks git --redact --verbose .
```

Có thể chạy kiểm tra staged changes thủ công bằng:

```bash
./.githooks/pre-commit
```

Để tắt hooks khi repository trước đó không có custom hook path:

```bash
git config --local --unset core.hooksPath
```

Nếu đã có custom hook path, hãy khôi phục chính xác giá trị cũ thay vì dùng `--unset`.

### Xử lý finding và giới hạn bảo vệ

- Không thêm allowlist chỉ để vượt qua lỗi. Trước tiên xác minh finding có phải credential thật
  hay không; fake/test value chỉ được ignore ở phạm vi nhỏ nhất và phải qua code review.
- Nếu secret thật mới chỉ được stage, bỏ nó khỏi commit, chuyển sang secret manager hoặc biến môi
  trường và cân nhắc rotate. Nếu đã từng được commit/push, revoke hoặc rotate ngay trước khi làm
  sạch Git history; xóa ở commit mới không loại secret khỏi lịch sử.
- `git commit --no-verify` và `git push --no-verify` có thể bỏ qua local hooks. Chỉ sử dụng khi có
  phê duyệt bảo mật và thực hiện scan thủ công tương đương.
- Hooks không thay thế secret scanning trong CI hoặc push protection phía Git hosting. Đây là lớp
  kiểm tra sớm trên máy developer; CI/server-side enforcement nên được bổ sung ở task riêng.

## GitHub Actions

Workflow chính chạy `quality`, sau đó khởi chạy SAST và ZAP Baseline DAST song song. Bên trong
reusable SAST workflow, Semgrep và CodeQL tiếp tục chạy ở hai job độc lập để không chờ nhau.
Mỗi job tự setup target vì filesystem và container không được chia sẻ giữa các runner.

Workflow **ZAP Full Scan DAST** là workflow độc lập, chỉ có `workflow_dispatch` và không chạy
trên push, pull request hoặc schedule. Mở workflow này trong tab **Actions**, chọn **Run
workflow** để tạo target cô lập, chạy `make dast-zap-fullscan`, validate report và cleanup.
Job có timeout 75 phút để bao phủ clone/build, spider, active scan và upload artifact.

Trước khi chạy workflow, vào **Settings → Secrets and variables → Actions**, tạo repository
secret `SEMGREP_APP_TOKEN` chứa token từ Semgrep AppSec Platform. Workflow chính chỉ truyền
named secret này vào reusable SAST workflow, và reusable workflow chỉ expose nó cho bước
`make sast-semgrep`. Secret là bắt buộc: pull request từ fork hoặc Dependabot không được GitHub cấp
repository secret sẽ fail SAST rõ ràng thay vì tạo report anonymous thiếu metadata.

Trong trang GitHub Actions, mở workflow run và tải artifact:

- `semgrep-raw-<run_id>`;
- `codeql-raw-<run_id>`;
- `zap-raw-<run_id>` từ Baseline workflow;
- `zap-fullscan-raw-<run_id>` từ Full Scan workflow thủ công;
- `normalized-findings-<run_id>` chứa unified JSONL và normalization summary;
- `dast-logs-<run_id>` nếu DAST thất bại.

Ngoài artifact raw, `reports/raw/codeql.sarif` được upload bằng
`github/codeql-action/upload-sarif@v4` để hiển thị trong tab **Security** của repository.
Mỗi ZAP raw artifact chứa `zap.json`, `zap.meta.json`, `zap-endpoints.txt` và
`zap-site-tree.yaml`. Artifacts được giữ 14 ngày.

## Cleanup

`make clean-reports` là lệnh duy nhất xóa nội dung sinh ra trong `reports/raw/` và
`reports/normalized/`; lệnh giữ lại `.gitkeep`.

`make clean` chạy `docker compose down --volumes --remove-orphans`, vì vậy container writable
data và mọi Compose volume của target bị xóa, rồi xóa chính xác clone
`target-app/juice-shop/`. Lệnh không xóa reports, lock, configs, docs, schemas hoặc source
Sentinel. Để tải lại target mà vẫn giữ kết quả scan: `make clean && make setup-target`.

## Troubleshooting

- Port 3000 bận: đặt `JUICE_SHOP_PORT` khác trong `.env`, rồi chạy lại `up`, `wait`, `smoke`.
- `ModuleNotFoundError: No module named '_sqlite3'` khi chạy `make kb-validate`: bản Python
  hiện tại (thường do pyenv build trước khi cài SQLite headers) không có extension SQLite. Chạy
  lại `make install`; bootstrap sẽ tự kiểm tra Python >=3.11, SQLite JSON/FTS5 và tạo lại `.venv`
  bằng runtime phù hợp. Có thể chỉ định rõ system Python bằng
  `make install PYTHON=/usr/bin/python3`. Không chạy `pip install sqlite3`: `_sqlite3` là thành
  phần của CPython, không phải package pip. Với pyenv trên Ubuntu/Debian, cài
  `libsqlite3-dev`, rồi cài lại phiên bản Python của pyenv trước khi tạo lại môi trường.
- `ModuleNotFoundError: No module named 'jsonschema'` khi chạy `make normalize`: shell hiện tại
  chưa dùng project virtualenv. Chạy `source .venv/bin/activate` rồi chạy lại; nếu `.venv` chưa
  tồn tại hoặc thiếu dependency, chạy `make install` trước. Không cài riêng `jsonschema` vào
  system Python để né project environment.

- Docker daemon/permission: chạy `make doctor`, khởi động Docker Desktop/daemon và bảo đảm user
  có quyền dùng Docker.
- Semgrep báo thiếu token hoặc `requires login`: thay placeholder trong `.env` hoặc export
  `SEMGREP_APP_TOKEN` hợp lệ; không commit hay in token ra log.
- CodeQL checksum mismatch: không bỏ qua kiểm tra; xóa Docker build cache liên quan và xác minh
  version/asset trên release chính thức trước khi thử lại.
- CodeQL báo `out of Java heap`: tăng memory Docker Engine/Desktop lên ít nhất 4 GiB rồi chạy
  lại; không giảm query suite hoặc bỏ qua query bị lỗi.
- ZAP Automation báo lỗi trước scan: chạy lại và đọc output `-autocheck`; không bỏ qua lỗi YAML
  hoặc đổi sang packaged scan flags vì plan trong `configs/zap/` là scope contract.
- Target dirty: không reset tự động; chạy `git -C target-app/juice-shop status`, review thay đổi,
  rồi dùng `make clean && make setup-target` nếu muốn tải lại hoàn toàn.
- Sai commit/remote/tag: `make verify-target` in expected/actual; dùng full reset nếu clone không đúng.
- ZAP Full Scan báo thiếu 4 GiB: tăng Docker Engine/Desktop memory; runner không fallback vì
  Client Spider là bắt buộc.
- ZAP Full Scan hết thời gian: kiểm tra log spider/active scan; giới hạn local là 10/30 phút và
  GitHub job timeout là 75 phút.
- ZAP Full Scan không khởi động hoặc trả code ngoài `0`/`2`: xem
  `logs/zap-fullscan-runner.log` và `logs/zap-fullscan-zap.out`; validator không chạy khi scanner
  chưa tạo report.
- Full Scan preflight báo sai version hoặc Automation plan không hợp lệ: image/config hiện tại
  không đáp ứng contract; không bỏ qua preflight để tạo report không tương thích.
- Thiếu/rỗng `zap-endpoints.txt` hoặc `zap-site-tree.yaml`: scan chưa hoàn tất export job; xem
  Automation output. Nếu export chứa origin ngoài Juice Shop, coi là scope regression và không
  upload report như một scan hợp lệ.
- ZAP code `2` là warning được chấp nhận; code `1`, `3` hoặc code khác là execution failure.
- ZAP không thấy network: bảo đảm `make up` thành công và network `sentinel-security` tồn tại.
