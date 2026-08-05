# Project Sentinel — Week 2

Môi trường DevSecOps có thể tái lập để chạy OWASP Juice Shop `v20.1.1`, quét mã nguồn
bằng Semgrep cùng CodeQL, quét web thụ động bằng OWASP ZAP Baseline và chạy ZAP Full Scan
chủ động theo yêu cầu. Source Juice Shop, generated raw reports và runtime logs không được commit
vào repository Sentinel.

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

Kết quả nằm tại `reports/raw/zap.json`; metadata `reports/raw/zap.meta.json` có
`scan_profile=baseline`. Nếu một bước lỗi trước cleanup, vẫn chạy `make down`.

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

Ngoài `zap.json` và metadata có `scan_profile=full`, log chẩn đoán được ghi tại
`logs/zap-fullscan-runner.log` và `logs/zap-fullscan-zap.out`.

Baseline và Full Scan dùng chung `reports/raw/zap.json`; profile chạy sau ghi đè kết quả profile
trước. Hãy sao chép hoặc upload report trước khi chuyển profile nếu cần giữ cả hai. Không chạy hai
profile đồng thời. Với cả hai lifecycle, nếu một bước lỗi trước cleanup thì vẫn chạy `make down`.

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
| Scanner | `sast`, `sast-semgrep`, `sast-codeql`, `dast`, `dast-zap-fullscan`, `validate-reports` |
| Normalization | `normalize` |
| Knowledge Base | `kb-validate`, `kb-build-documents`, `kb-build-index`, `kb-build`, `kb-rebuild` |
| Knowledge Search | `kb-search`, `kb-inspect`, `kb-stats`, `kb-test`, `kb-lint` |
| Orchestration | `week1` |
| Cleanup | `kb-clean`, `clean-reports`, `clean` |

`wait` polling HTTP cho đến khi ứng dụng thực sự ready. `smoke` là kiểm tra riêng từ host,
yêu cầu HTTP 2xx/3xx và response body không rỗng. `lint` chạy full Ruff trên `src/`, `tests/`
và Python scripts, sau đó kiểm tra Bash syntax cùng Docker Compose configuration.

## SAST và DAST

`make sast-semgrep` chạy Semgrep theo đúng luồng hiện có; `make sast` gọi target này trước rồi
gọi `make sast-codeql`. Semgrep chạy image `semgrep/semgrep:1.171.0` trên duy nhất
phần runtime của `target-app/juice-shop/`, dùng các Registry ruleset `p/owasp-top-ten`,
`p/javascript`, `p/nodejs` và `p/expressjs`. Report được ghi tại
`reports/raw/semgrep.json`.

Scope SAST được quản lý bằng allowlist `configs/semgrep/includes.txt` và denylist
`configs/semgrep/.semgrepignore`. Semgrep chuyển hai danh sách này thành `--include`/`--exclude`;
CodeQL có cấu hình tương đương, độc lập tại `configs/codeql/code-scanning.yml`. Phần được quét
gồm entry point `app.ts`, `server.ts`, backend `routes/`, `lib/`, `models/`, runtime data/config,
views và Angular `frontend/src/`. Test/spec, CI config, output build, dependency đã cài và
`data/static/codefixes/` bị loại. Mỗi scanner chạy validator hậu kiểm report; chỉ một artifact
ngoài scope cũng làm job thất bại.

`node_modules/` không được đưa vào SAST. Semgrep và CodeQL ở pipeline này phân tích source để
tìm lỗi luồng dữ liệu/cách dùng API; chúng không thay thế Software Composition Analysis (SCA)
để đối chiếu package/version với cơ sở dữ liệu CVE. Khi bổ sung SCA, nên quét manifest/lockfile
hoặc SBOM bằng một job riêng và giữ kết quả tách khỏi phép đo overlap SAST/DAST.

Scan SAST yêu cầu `SEMGREP_APP_TOKEN` hợp lệ. Local runner ưu tiên biến đã export, sau đó đọc
đúng khóa này từ `.env` mà không thực thi toàn bộ file:

```bash
export SEMGREP_APP_TOKEN='<token>'
make sast-semgrep
```

Có thể thay bằng cách điền token vào `.env`. Không echo, truyền token trên command line hoặc
commit `.env`. Scanner chỉ truyền tên biến vào container và sẽ fail trước khi scan nếu token
thiếu, rỗng hoặc còn là placeholder. Sau scan, task cũng từ chối report nếu metadata finding
vẫn chứa `"requires login"`.

Đăng nhập Registry cho phép Semgrep trả metadata đầy đủ và các rule/tính năng bổ sung tùy theo
entitlement của deployment. Luồng này vẫn dùng `semgrep scan`, không upload kết quả bằng
`semgrep ci` và không tự thay đổi sản phẩm đã bật trên Semgrep AppSec Platform.

Scanner image được pin version, nhưng Semgrep Registry là cấu hình remote: nội dung ruleset
có thể thay đổi dù image không đổi. Đây là giới hạn được chấp nhận trong Week 1. Ruleset mở
rộng chưa bật mặc định gồm `p/typescript`, `p/security-audit`, `p/cwe-top-25`, `p/docker`;
secret scanning nên là bước riêng trong tương lai.

`make sast-codeql` build image nội bộ từ `ubuntu:24.04` và CodeQL bundle chính thức. Version
được đọc duy nhất từ `CODEQL_VERSION` trong `configs/tool-versions.env`; Dockerfile và CI tự
dựng URL release tương ứng. Bundle cùng file `.checksum.txt` được tải từ
`github/codeql-action/releases` và phải vượt qua `sha256sum -c` trước khi giải nén.

CodeQL tạo database JavaScript/TypeScript tại `/tmp/codeql-db` trong container, sau đó chạy
suite `javascript-security-extended.qls` với ngân sách RAM 3000 MiB, query help và ghi SARIF
tại `reports/raw/codeql.sarif`. Cả local runner và CI truyền `--sarif-add-snippets`; CodeQL vì
vậy thêm `physicalLocation.region.snippet.text` cho các vị trí kết quả, gồm hai dòng ngữ cảnh
trước và sau vị trí được báo cáo. Cờ này chỉ bổ sung code snippet vào raw SARIF, không thêm toàn
bộ nội dung file như `--sarif-add-file-contents`.

Unified Findings v1 chưa đưa raw snippet vào `evidence` hoặc `data_flow.content`; hai trường này
tiếp tục giữ chính sách hiện có cho tới khi có redaction và trust-boundary phù hợp. Database
CodeQL không được mount nên tự mất khi container `--rm` kết thúc. Source Juice Shop và cấu hình
scope được mount read-only; report được ghi bằng UID/GID của host để tránh file thuộc sở hữu
root. Target luôn gọi `docker compose build` trước scan và dựa vào Docker layer cache, vì vậy
lần chạy sau chỉ rebuild khi version hoặc Dockerfile thay đổi.

Service `codeql-scan` thuộc Compose profile `scan`, nên không chạy theo `docker compose up`.
Không cần cài CodeQL trên host; cần chạy `make setup-target` trước khi scan.

`make dast` và `make dast-zap-fullscan` chỉ scan; chúng không build, start hoặc stop target.
Hãy chạy `make build`, `make up`, `make wait` và `make smoke` trước. Cả hai dùng image đã pin
`ghcr.io/zaproxy/zaproxy:2.17.0` và chỉ truy cập URL cố định `http://juice-shop:3000` trong
network `sentinel-security`; runner không nhận target URL tùy ý.

ZAP Baseline chạy passive scan. Khi Docker có ít nhất 4 GiB RAM, runner truyền đồng thời
`-j --client-spider`; nếu thiếu RAM, Baseline dùng Traditional Spider. Client Spider render
JavaScript để khám phá Angular routes/endpoints mà Traditional Spider chỉ đọc HTML và
`<a href>` không nhìn thấy.

ZAP Full Scan chạy spider rồi active scan có gửi payload kiểm thử. Runner Full Scan luôn truyền
cả `-j` và `--client-spider`; thiếu một flag sẽ không đạt repository contract. Full Scan fail-fast
khi Docker có dưới 4 GiB RAM thay vì âm thầm bỏ Client Spider. Traditional/Client Spider được
giới hạn 10 phút, passive/start wait 10 phút và toàn bộ active scan 30 phút bằng
`scanner.maxScanDurationInMins=30`.

Trước Full Scan, runner xác nhận core version khớp `ZAP_VERSION` và packaged script hỗ trợ
`--client-spider`. ZAP daemon ghi `/zap/zap.out` qua bind mount thuộc UID/GID host; log được giữ
tại `logs/zap-fullscan-zap.out`, còn stdout/stderr của packaged scan nằm tại
`logs/zap-fullscan-runner.log` để dùng được cả local và CI.

Cả Baseline và Full Scan ghi `reports/raw/zap.json` cùng `zap.meta.json`. Metadata phân biệt
`scan_profile` là `baseline` hoặc `full`; scanner chạy sau ghi đè report ZAP trước đó và
`make normalize` sẽ dùng report mới nhất. Exit code `1` hoặc `2` biểu thị findings và vẫn được
xem là scan hoàn tất; exit code `3`, code lạ hoặc report không hợp lệ làm task thất bại.

Runner truyền `-silent` để không tự update hoặc cài add-on trong lúc scan; scanner behavior vì
vậy bám theo image đã pin. Chỉ chạy Full Scan trên target được cấp phép và không dùng script
này để scan production hay hệ thống ngoài `TARGET.lock`.

Các scanner container chạy bằng UID/GID của host để raw reports không thuộc sở hữu root.

## Unified findings normalization

Mỗi scanner tạo raw report cùng sidecar metadata tại scan boundary. Sau khi chạy đủ SAST và
DAST, `make normalize` ghi `reports/normalized/unified-findings.jsonl` và
`normalization-summary.json`. Chi tiết data contract, failure policy và CLI nằm tại
[`docs/reports/week2/week-2-normalization.md`](docs/reports/week2/week-2-normalization.md).

Normalizer dùng các dependency Python đã cài trong project virtualenv. Luôn kích hoạt `.venv`
trong shell hiện tại trước khi validate hoặc normalize report:

```bash
make install
source .venv/bin/activate
make validate-reports
make normalize
```

Mỗi scanner cần một cặp report/metadata trong `reports/raw/`:

| Scanner | Finding report | Metadata sidecar |
| --- | --- | --- |
| Semgrep | `semgrep.json` | `semgrep.meta.json` |
| ZAP Baseline hoặc Full Scan | `zap.json` | `zap.meta.json` |
| CodeQL | `codeql.sarif` | `codeql.meta.json` |

Metadata là input bắt buộc vì cung cấp scan run ID, thời điểm quét, phiên bản CLI và target
identity cần cho audit/provenance của Unified Finding. `semgrep.sarif` và `zap.yaml` không phải
input của normalizer.

Khi tải artifact từ GitHub Actions, giải nén report và sidecar tương ứng vào cùng
`reports/raw/`. Với Full Scan, dùng cả `zap.json` và `zap.meta.json` trong artifact
`zap-fullscan-raw-<run_id>`; không ghép report của một workflow với metadata của workflow khác.

`make validate-reports` kiểm tra cả sáu artifact và liệt kê toàn bộ file thiếu hoặc không hợp lệ
trước khi exit non-zero. `make normalize` vẫn tạo output nếu còn ít nhất một cặp hợp lệ: scanner
thiếu report/metadata có `status: "skipped"`, `reason: "missing_input"` trong summary. File đã
tồn tại nhưng rỗng, malformed hoặc metadata không hợp lệ có `status: "failed"`; findings hợp lệ
từ scanner khác vẫn được ghi nhưng command exit non-zero. Nếu không có cặp nào thành công,
normalizer không tạo success output giả.

Inventory và quyết định thiết kế cho Security Knowledge Base được theo dõi tại
[`docs/reports/week2/week-2-knowledgebase.md`](docs/reports/week2/week-2-knowledgebase.md).

Integration tests dùng các scanner snapshot cố định trong `tests/fixtures/scanners/`. Các file
cùng tên dưới `reports/raw/` chỉ là output runtime đã được ignore; chạy scanner hoặc
`make clean-reports` vì vậy không sửa hay xóa fixture của test.

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
Artifacts được giữ 14 ngày.

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
- ZAP code 3 kèm `Failed to access summary file /tmp/zap_out.json`: kiểm tra Docker OOM events
  và cấp ít nhất 4 GiB memory cho Docker Engine/Desktop; Client Spider chạy browser thật nên
  cần nhiều memory hơn Traditional Spider.
- Target dirty: không reset tự động; chạy `git -C target-app/juice-shop status`, review thay đổi,
  rồi dùng `make clean && make setup-target` nếu muốn tải lại hoàn toàn.
- Sai commit/remote/tag: `make verify-target` in expected/actual; dùng full reset nếu clone không đúng.
- ZAP Full Scan báo thiếu 4 GiB: tăng Docker Engine/Desktop memory; runner không fallback vì
  Client Spider là bắt buộc.
- ZAP Full Scan hết thời gian: kiểm tra log spider/active scan; giới hạn local là 10/30 phút và
  GitHub job timeout là 75 phút.
- ZAP Full Scan báo `Failed to start ZAP :(` hoặc code `3`: xem
  `logs/zap-fullscan-runner.log` và `logs/zap-fullscan-zap.out`; validator không chạy khi scanner
  chưa tạo report.
- Full Scan preflight báo thiếu `--client-spider` hoặc sai version: image ứng với tag hiện tại
  không đáp ứng contract; không bỏ flag hoặc bỏ qua kiểm tra để tạo report không tương thích.
- ZAP code 1/2: đây là findings, không phải scanner crash; code 3 mới là execution failure.
- ZAP không thấy network: bảo đảm `make up` thành công và network `sentinel-security` tồn tại.
