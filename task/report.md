# Báo cáo sửa lỗi và bổ sung CodeQL SARIF snippets

## Phạm vi

Task sửa Python test workflow, harden CodeQL normalizer, bổ sung CLI/error-path tests, tách
repository contract suite, bật source snippets trong raw CodeQL SARIF và cập nhật tài liệu.
Unified Findings schema vẫn là `1.0.0`; `evidence` và `data_flow.content` chưa nhận raw snippet.

Raw ZAP active-scan được bảo vệ trong toàn bộ task. Không chạy ZAP, `make normalize`,
`make clean-reports` hoặc command ghi vào `reports/raw/zap*`. Finding active-scan trong raw ZAP
vẫn chưa được đưa vào `unified-findings` bởi task này.

## Các commit

### `dd2e73b` — `fix(test): run Python tests from the project virtualenv`

- Chuyển `test-python` sang `.venv/bin/python` cùng preflight hiện có.
- Cho CI quality job cài project bằng `make install`.
- Thêm contract assertions cho Python runtime local và CI.
- Kiểm tra tại commit: `make test`, 40 Python tests pass.

### `a001abe` — `fix(codeql): validate SARIF rule descriptor identity`

- Xác nhận descriptor tại `ruleIndex` có ID khớp `result.ruleId`.
- Fallback theo rule ID và giữ đúng JSON Pointer khi index không nhất quán.
- Thêm test cho nguồn/fallback của `description`, descriptor thiếu/sai và SARIF malformed.
- Kiểm tra tại commit: 11 CodeQL unit/integration tests và Ruff pass.

### `3889745` — `test(normalizers): cover CLI success and failure contracts`

- Thêm bốn integration tests cho single-tool, aggregate partial success, invalid schema và
  invalid metadata.
- Chuyển schema setup error thành exit code `1` và failure summary, không lộ traceback.
- Tất cả report/metadata trong test được tạo dưới `tmp_path`.
- Kiểm tra tại commit: 4 CLI integration tests và Ruff pass.

### `0a2c630` — `test(contracts): split repository contract test suite`

- Tách script 499 dòng thành runner, common helper và năm module theo subsystem.
- Giữ đủ 154 failure assertions và fail-fast behavior.
- Report-validation tests chỉ ghi vào temporary directory.
- Kiểm tra tại commit: Bash syntax và `make test-contracts` pass.

### `79c6a10` — `feat(codeql): include source snippets in raw SARIF`

- Thêm `--sarif-add-snippets` vào CodeQL local Compose và GitHub Actions.
- Thêm contract assertions cho cả hai scan path.
- Thêm regression test chứng minh normalizer v1 không ingest snippet vào `evidence` hoặc
  `data_flow.content`.
- CodeQL/contract tests và `docker compose config --quiet` pass.
- Full `make sast-codeql` chưa xác minh được: Docker Desktop socket
  `/home/huan/.docker/desktop/docker.sock` không tồn tại. Scan dừng trước khi tạo database hoặc
  ghi report CodeQL.

### `9e00823` — `docs(codeql): document SARIF snippet capture`

- Cập nhật README, kiến trúc và Week 2 normalization spec.
- Ghi rõ cờ `--sarif-add-snippets`, vị trí `physicalLocation.region.snippet.text`, hai dòng
  context trước/sau và raw-only trust boundary.
- Thêm documentation contract để tránh vô tình mô tả rằng v1 đã ingest snippet.
- Kiểm tra tại commit: `make test-contracts` pass.

### Current commit — `docs(task): add implementation and commit report`

- Thêm báo cáo này với commit inventory, test results, runtime limitation và ZAP integrity.

## Kiểm tra cuối

- `make test`: 55 tests pass, cùng toàn bộ repository contracts và KB Python bootstrap test.
- `make kb-test`: 105 tests pass.
- `make kb-lint`: pass.
- Full Ruff trên `src`, `tests`, `scripts`: pass.
- Bash syntax cho scripts và contract modules: pass.
- `docker compose --env-file configs/tool-versions.env config --quiet`: pass.
- `git diff --check`: pass.
- Target Juice Shop working tree: clean.

## ZAP integrity

Checksum trước và sau task giống nhau:

| Artifact | SHA-256 |
| --- | --- |
| `reports/raw/zap.json` | `7c1bb88c51ff7c7356cdea8783b3d0a93647728a341520e9d41d1fa74028f449` |
| `reports/raw/zap.meta.json` | `9021d0097043f2c2e162aab1320c159bba5636b999839b2fe49ad7df3f19a971` |
| `reports/raw/zap.yaml` | `cdccee34e070e8c109cbbd14d17e8d8870679d2cd3f20844ea6c9242aef7211c` |

Không artifact ZAP nào bị thay thế hoặc sửa đổi.
