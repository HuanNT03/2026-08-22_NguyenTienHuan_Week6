# Week 1 scanner findings

## Scan metadata

| Thuộc tính | Giá trị |
| --- | --- |
| Target | OWASP Juice Shop `v20.1.1` |
| Commit | `f915bddd82790d0f3018902d36ae9b4241a5f51f` |
| Semgrep | `1.171.0` |
| CodeQL | `2.26.0` |
| ZAP | `2.17.0` |
| Scan status | Local SAST and DAST completed; reports validated |
| Raw SAST reports | `reports/raw/semgrep.json`, `reports/raw/codeql.sarif` |
| Raw DAST report | `reports/raw/zap.json` |
| CI artifacts | `semgrep-raw-<run_id>`, `codeql-raw-<run_id>`, `zap-raw-<run_id>` |

## Commands and scope

SAST dùng `make sast`: Semgrep chạy `p/owasp-top-ten`, `p/javascript`, `p/nodejs`,
`p/expressjs`; CodeQL chạy `javascript-security-extended.qls`. Cả hai chỉ phân tích runtime
scope được khai báo trong `configs/semgrep/` và `configs/codeql/code-scanning.yml`. Test/spec,
CI config, build output, `node_modules/` và `data/static/codefixes/` bị loại. DAST dùng
`make dast` với ZAP Baseline spider/passive scan; không chạy Active hoặc Full Scan.

## Results

Sau khi áp dụng scope mới và quét lại ngày 2026-08-03, Semgrep sinh 37 findings trên 521
source artifacts: 14 `CRITICAL`, 5 `ERROR` và 18 `WARNING`. CodeQL sinh 87 findings trên 428
source artifacts. Validator xác nhận không có artifact/result từ `.github/`,
`data/static/codefixes/` hoặc `node_modules/`. Đây vẫn là scanner output chưa được triage hoặc
deduplicate; thay đổi scope không tự giải quyết việc correlate theo `fingerprint`/`group_key`.

ZAP Baseline spider được 158 URL và kết thúc với code `2` (WARN, được chấp nhận trong Week 1). Raw JSON có 4 alert families: CSP header chưa được đặt (Medium/High, 5 instances), cross-domain misconfiguration (Medium/Medium, 2), Unix timestamp disclosure (Low/Low, 3 unique instances trong JSON) và modern web application (Informational/Medium, 5). Không có alert loại FAIL trong lần chạy này.

Cả `semgrep.json` và `zap.json` đã qua `make validate-reports`, thuộc UID/GID `1000:1000`, mode `0644`; vì vậy local cleanup và CI artifact upload có thể đọc file mà không cần `sudo chown`. Raw reports vẫn bị Git ignore và chỉ dùng làm local output/CI artifact.

## Limitations

- Semgrep Registry ruleset là remote configuration và có thể thay đổi theo thời gian.
- SAST và DAST có false positive/false negative; Week 1 chưa correlate hoặc deduplicate.
- ZAP Baseline chỉ thực hiện spider và passive scan.
- `data/static/codefixes/` chỉ là nguồn tạo ground truth tương lai, không nằm trong SAST runtime scope.
- Semgrep/CodeQL trong pipeline này không phải SCA; dependency CVE và SBOM cần job riêng.
- Week 1 chưa có ground truth curated, precision/recall hoặc benchmark scanner.
