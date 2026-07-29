# Project Sentinel — Week 1

Môi trường DevSecOps có thể tái lập để chạy OWASP Juice Shop `v20.1.1`, quét mã nguồn
bằng Semgrep và quét web thụ động bằng OWASP ZAP Baseline. Source Juice Shop, raw reports
và runtime logs không được commit vào repository Sentinel.

## Mục lục

- [Phạm vi](#phạm-vi)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Quickstart](#quickstart)
- [Các lệnh Make](#các-lệnh-make)
- [SAST và DAST](#sast-và-dast)
- [GitHub Actions](#github-actions)
- [Cleanup](#cleanup)
- [Troubleshooting](#troubleshooting)

## Phạm vi

Week 1 triển khai target pinning, Docker lifecycle, Semgrep SAST, ZAP Baseline DAST,
raw JSON validation và CI artifacts. Normalization, RAG, AI Agent, Gateway, guardrails,
ground-truth evaluation và scanner correlation được dành cho các tuần sau.

## Yêu cầu hệ thống

- Linux x86_64, macOS với Docker Desktop, hoặc Windows WSL2 với Docker Desktop;
- Git, Bash, GNU Make, Docker Engine/Desktop, Docker Compose v2;
- `curl` và `jq`.

Không cần cài Node.js, Semgrep hoặc ZAP trên host. Chạy `make doctor` để kiểm tra môi trường.

## Quickstart

```bash
make doctor
make setup-target
make build
make up
make wait
make smoke
make sast
make dast
make validate-reports
make down
```

Hoặc chạy toàn bộ luồng với cleanup runtime tự động:

```bash
make week1
```

Thứ tự của `week1` là `doctor → quality → setup-target → sast → build → up → wait →
smoke → dast → validate-reports → down`. SAST chạy trước build vì không phụ thuộc runtime.

Port host mặc định là `127.0.0.1:3000`. Copy `.env.example` thành `.env` để đổi
`JUICE_SHOP_PORT`. Container vẫn lắng nghe port `3000` trên network `sentinel-security`.

## Các lệnh Make

Chạy `make help` để xem danh sách đầy đủ. Các nhóm lệnh chính:

| Nhóm | Lệnh |
| --- | --- |
| Môi trường | `doctor`, `lint`, `test`, `quality` |
| Target | `setup-target`, `verify-target` |
| Runtime | `build`, `up`, `wait`, `smoke`, `status`, `logs`, `down` |
| Scanner | `sast`, `dast`, `validate-reports` |
| Orchestration | `week1` |
| Cleanup | `clean-reports`, `clean` |

`wait` polling HTTP cho đến khi ứng dụng thực sự ready. `smoke` là kiểm tra riêng từ host,
yêu cầu HTTP 2xx/3xx và response body không rỗng.

## SAST và DAST

`make sast` chạy image `semgrep/semgrep:1.171.0` trên duy nhất
`target-app/juice-shop/`, dùng các Registry ruleset `p/owasp-top-ten`, `p/javascript`,
`p/nodejs` và `p/expressjs`. Report được ghi tại `reports/raw/semgrep.json`.

Scanner image được pin version, nhưng Semgrep Registry là cấu hình remote: nội dung ruleset
có thể thay đổi dù image không đổi. Đây là giới hạn được chấp nhận trong Week 1. Ruleset mở
rộng chưa bật mặc định gồm `p/typescript`, `p/security-audit`, `p/cwe-top-25`, `p/docker`;
secret scanning nên là bước riêng trong tương lai.

`make dast` chỉ scan; nó không build, start hoặc stop target. Hãy chạy `make build`, `make up`,
`make wait` và `make smoke` trước. ZAP Baseline chỉ spider/passive scan và ghi
`reports/raw/zap.json`. Exit code `1` hoặc `2` biểu thị findings, vẫn được xem là scan hoàn tất;
exit code `3` hoặc report không hợp lệ làm task thất bại.

Runner truyền `-z "-silent"` cho ZAP Baseline để không tự update hoặc cài add-on trong lúc scan; scanner behavior vì vậy bám theo image đã pin.

Hai scanner chạy container bằng UID/GID của host để raw reports không thuộc sở hữu root.

## GitHub Actions

Workflow chính chạy `quality`, sau đó khởi chạy SAST và DAST song song trên hai runner
`ubuntu-24.04`. Mỗi job tự setup target vì filesystem và container không được chia sẻ.

Trong trang GitHub Actions, mở workflow run và tải artifact:

- `semgrep-raw-<run_id>`;
- `zap-raw-<run_id>`;
- `dast-logs-<run_id>` nếu DAST thất bại.

Artifacts được giữ 14 ngày.

## Cleanup

`make clean-reports` chỉ xóa nội dung sinh ra trong `reports/raw/` và
`reports/normalized/`, đồng thời giữ `.gitkeep`.

`make clean` dừng Compose resources, xóa generated reports và xóa chính xác clone
`target-app/juice-shop/`. Nó không xóa lock, configs, docs, schemas hoặc source Sentinel.
Để tải lại target: `make clean && make setup-target`.

## Troubleshooting

- Port 3000 bận: đặt `JUICE_SHOP_PORT` khác trong `.env`, rồi chạy lại `up`, `wait`, `smoke`.
- Docker daemon/permission: chạy `make doctor`, khởi động Docker Desktop/daemon và bảo đảm user
  có quyền dùng Docker.
- Target dirty: không reset tự động; chạy `git -C target-app/juice-shop status`, review thay đổi,
  rồi dùng `make clean && make setup-target` nếu muốn tải lại hoàn toàn.
- Sai commit/remote/tag: `make verify-target` in expected/actual; dùng full reset nếu clone không đúng.
- ZAP code 1/2: đây là findings, không phải scanner crash trong Week 1.
- ZAP không thấy network: bảo đảm `make up` thành công và network `sentinel-security` tồn tại.
