# AGENTS.md — Project Sentinel

Tệp này áp dụng cho toàn bộ repository. Đây là hướng dẫn vận hành dành cho coding
agent; yêu cầu trực tiếp của người dùng luôn có độ ưu tiên cao hơn. Khi tài liệu và
implementation mâu thuẫn, không âm thầm đoán: kiểm tra source of truth bên dưới, nêu rõ
mâu thuẫn và chỉ sửa trong phạm vi task được giao.

## Mục tiêu và phạm vi

Hệ thống dùng OWASP Juice Shop `v20.1.1` làm target được cấp phép để:

1. chạy SAST/DAST bằng Semgrep, CodeQL và OWASP ZAP;
2. chuẩn hóa scanner output thành Unified Findings JSONL;
3. truy hồi tri thức bảo mật từ knowledge base;
4. dùng Security Analysis Agent để tạo báo cáo có căn cứ;
5. Đưa request kiểm thử an toàn qua API Gateway, human approval và guardrails.

## Source of truth

Ưu tiên các nguồn sau theo loại thông tin:

- Yêu cầu và definition of done theo
  `docs/[NCUD-GPAI] VinUni x VinSOC 6-week of Project.md`.
- Lệnh thực thi hiện có theo `Makefile`; không sao chép tên lệnh từ tài liệu cũ mà
  không đối chiếu lại.
- Unified Finding contract theo `schemas/unified_findings.schema.json` và code trong
  `src/normalizers/`.
- Knowledge Document contract theo `schemas/knowledge_document.schema.json` và code
  trong `src/retrieval/`.
- Target repository, tag và commit theo `target-app/TARGET.lock`.
- Hướng dẫn vận hành và trạng thái implementation theo `README.md` cùng các tài liệu
  `docs/week-*.md`.
- Phiên bản scanner/tool theo `configs/tool-versions.env` và image/config tương ứng.

JSON Schema là nguồn chuẩn cho field, required property, enum và validation. Không đổi
schema hoặc data contract chỉ để làm một test cục bộ pass; mọi thay đổi contract phải
được cập nhật đồng bộ code, test, fixture và tài liệu liên quan.

## Cấu trúc repository

Đặt code mới đúng vai trò, không tạo cây thư mục song song:

```text
.github/workflows/       CI, SAST và DAST workflows
configs/                 cấu hình và version đã pin của security tools
docs/                    kiến trúc, contract, báo cáo và decision log
ground-truth/            dữ liệu generated/curated theo human review policy
knowledge-base/          raw sources, curated examples, canonical data và FTS index
reports/raw/             scanner outputs/fixtures
reports/normalized/      generated Unified Findings và normalization summary
schemas/                 JSON Schema cho các data contract
scripts/                 orchestration và environment checks
src/normalizers/         scanner output -> Unified Findings
src/retrieval/           knowledge build, SQLite FTS5 và public search service
target-app/              TARGET.lock và clone Juice Shop được gitignore
tests/                    unit, integration, retrieval và contract tests
```

Khi triển khai Week 3, dùng `src/agent/` cho orchestration/model logic,
`src/agent/prompts/` cho versioned system prompt và `tests/agent/` cho test. Không đặt
agent logic trong `src/retrieval/` hoặc `src/normalizers/`.

## Data contract và dữ liệu được bảo vệ

### Unified Findings

- Mỗi dòng trong file `reports/normalized/unified-findings-YYYYMMDDTHHMMSSZ.jsonl` là
  một object hợp lệ theo `schemas/unified_findings.schema.json`. Downstream phải nhận
  exact output path từ normalizer; không dùng glob để tự chọn file mới nhất.
- Giữ nguyên công thức canonical hashing cho `fingerprint` và `group_key` trong
  normalizer hiện tại. Không tạo công thức gần giống ở agent.
- `raw_sources[].json_pointer` phải tiếp tục truy vết được về scanner record gốc.

### Generated artifacts và fixtures

- Không sửa `target-app/juice-shop/`; đây là clone sinh từ `TARGET.lock`. Nếu target
  dirty, dừng và báo thay vì reset hoặc sửa tự động.
- `reports/normalized/*`, runtime logs và SQLite index là generated/ignored artifacts.
- `reports/raw/*` là generated/ignored scanner output. Tracked scanner fixtures nằm ở
  `tests/fixtures/scanners/`; không cập nhật chúng ngoài một task thay đổi fixture có
  chủ đích và phải kiểm tra secret trước khi commit.
- Trước khi sửa generated canonical knowledge data, sửa nguồn/parser rồi rebuild bằng
  pipeline; không hand-edit JSONL hoặc SQLite.

## Workflow

Đọc file liên quan và test hiện có trước khi sửa. Giữ thay đổi nhỏ, có test tương ứng và
không sửa unrelated user changes trong working tree.

### Phân tách task nhỏ và Git commit
- Khi thực hiện các công việc phức tạp hoặc gồm nhiều bước, agent cần phân tách yêu cầu thành từng kế hoạch chi tiết riêng biệt, có cột mốc để xác định đã thực hiện hay chưa, mỗi bản kế hoạch lại bao gồm nhiều task nhỏ, độc lập và rõ ràng.
- Sau khi thực hiện xong mỗi task nhỏ (bao gồm chỉnh sửa file, kiểm thử/validate), agent phải commit ngay thay đổi vào git với commit message mô tả rõ nội dung task trước khi chuyển sang task tiếp theo.

### Test-first và function contract

- Trước khi triển khai hoặc thay đổi bất kỳ function nào, phải xác định và viết rõ các
  test case cùng expected result trước. Tối thiểu xem xét happy path, boundary/missing
  value, invalid input, failure behavior, edge case và security case liên quan; không bắt đầu viết
  implementation khi chưa biết function sẽ được chứng minh đúng bằng test nào.
- Test phải kiểm tra behavior/contract quan sát được, không khóa chặt chi tiết
  implementation không cần thiết. Với bug fix, thêm regression test tái hiện lỗi trước
  khi sửa function.
- Mỗi function mới hoặc function được thay đổi đáng kể phải có docstring giải thích
  đầy đủ: mục đích, ý nghĩa của hàm và các ràng buộc của từng input, kiểu/shape và ý nghĩa của output,
  failure/exception có chủ đích, cùng side effect hoặc trust boundary nếu có.
- Với function không trả dữ liệu, docstring phải nói rõ output là `None` và side effect
  tạo ra. Với function trả structured object/tuple, mô tả từng thành phần thay vì chỉ
  ghi tên type.
- Khi review diff, đối chiếu từng function mới/đã đổi với test case và docstring tương
  ứng; thiếu một trong hai thì thay đổi chưa đạt definition of done.

Python yêu cầu 3.11+. Tuân thủ `pyproject.toml`, Pydantic v2, pytest và Ruff hiện có.

## Tiêu chuẩn hoàn thành thay đổi

- Implementation, schema, tests và documentation nhất quán với nhau.
- Error message có context hành động được nhưng không chứa secret hoặc raw untrusted
  payload không cần thiết.
- Báo cáo cuối task nêu file đã đổi, test đã chạy và giới hạn/chưa xác minh còn lại.
