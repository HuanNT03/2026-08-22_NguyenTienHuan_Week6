# Week 1 scanner findings

## Scan metadata

| Thuộc tính | Giá trị |
| --- | --- |
| Target | OWASP Juice Shop `v20.1.1` |
| Commit | `f915bddd82790d0f3018902d36ae9b4241a5f51f` |
| Semgrep | `1.171.0` |
| ZAP | `2.17.0` |
| Scan status | Local SAST and DAST completed; reports validated |
| Raw SAST report | `reports/raw/semgrep.json` |
| Raw DAST report | `reports/raw/zap.json` |
| CI artifacts | `semgrep-raw-<run_id>`, `zap-raw-<run_id>` |

## Commands and scope

SAST dùng `make sast` với `p/owasp-top-ten`, `p/javascript`, `p/nodejs` và `p/expressjs`.
DAST dùng `make dast` với ZAP Baseline spider/passive scan. Không chạy Active hoặc Full Scan.

## Results

Semgrep sinh 38 findings: 19 `ERROR`, 17 `WARNING` và 2 `MEDIUM`. Các nhóm nổi bật gồm 6 tainted SQL string findings, 6 Express/Sequelize injection findings, 5 GitHub Actions shell-injection findings và 4 Express directory-listing findings. Đây là scanner output chưa được triage hoặc deduplicate; path trong raw JSON dùng mount prefix `/src/`.

ZAP Baseline spider được 158 URL và kết thúc với code `2` (WARN, được chấp nhận trong Week 1). Raw JSON có 4 alert families: CSP header chưa được đặt (Medium/High, 5 instances), cross-domain misconfiguration (Medium/Medium, 3), Unix timestamp disclosure (Low/Low, 3 unique instances trong JSON) và modern web application (Informational/Medium, 5). Không có alert loại FAIL trong lần chạy này.

Cả `semgrep.json` và `zap.json` đã qua `make validate-reports`, thuộc UID/GID `1000:1000`, mode `0644`; vì vậy local cleanup và CI artifact upload có thể đọc file mà không cần `sudo chown`. Raw reports vẫn bị Git ignore và chỉ dùng làm local output/CI artifact.

## Limitations

- Semgrep Registry ruleset là remote configuration và có thể thay đổi theo thời gian.
- SAST và DAST có false positive/false negative; Week 1 chưa correlate hoặc deduplicate.
- ZAP Baseline chỉ thực hiện spider và passive scan.
- Week 1 chưa có ground truth, precision/recall hoặc benchmark scanner.
