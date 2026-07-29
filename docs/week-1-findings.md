# Week 1 scanner findings

## Scan metadata

| Thuộc tính | Giá trị |
| --- | --- |
| Target | OWASP Juice Shop `v20.1.1` |
| Commit | `f915bddd82790d0f3018902d36ae9b4241a5f51f` |
| Semgrep | `1.171.0` |
| ZAP | `2.17.0` |
| Scan status | Not run yet |
| Raw SAST report | `reports/raw/semgrep.json` |
| Raw DAST report | `reports/raw/zap.json` |
| CI artifacts | `semgrep-raw-<run_id>`, `zap-raw-<run_id>` |

## Commands and scope

SAST dùng `make sast` với `p/owasp-top-ten`, `p/javascript`, `p/nodejs` và `p/expressjs`.
DAST dùng `make dast` với ZAP Baseline spider/passive scan. Không chạy Active hoặc Full Scan.

## Results

Counts theo severity/risk, thời gian scan, findings tiêu biểu, location/URL và evidence chưa được
ghi vì scanner chưa chạy. Sau khi chạy `make week1`, lấy số liệu trực tiếp từ raw JSON hợp lệ;
không copy số liệu từ target version hoặc lần scan khác.

## Limitations

- Semgrep Registry ruleset là remote configuration và có thể thay đổi theo thời gian.
- SAST và DAST có false positive/false negative; Week 1 chưa correlate hoặc deduplicate.
- ZAP Baseline chỉ thực hiện spider và passive scan.
- Week 1 chưa có ground truth, precision/recall hoặc benchmark scanner.
