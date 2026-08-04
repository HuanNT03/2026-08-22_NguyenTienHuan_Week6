# Báo cáo Week 2 — Chuẩn hóa kết quả quét và Knowledge Base

**Ngày báo cáo:** 01/08/2026  
**Mục tiêu:** chuyển đầu ra Semgrep, OWASP ZAP và CodeQL thành dữ liệu thống nhất để AI Agent sử dụng; đồng thời xây kho tri thức bảo mật nhỏ có khả năng tìm kiếm.

## 1. Kết quả thực hiện

Luồng **normalization** định nghĩa JSON Schema, chuẩn hóa mức độ nghiêm trọng/độ tin cậy/phân loại, vị trí code hoặc HTTP và data flow; xây dựng bộ đọc và chuẩn hóa riêng cho kết quả Semgrep JSON, OWASP ZAP JSON và CodeQL SARIF, chuyển đầu ra của ba scanner về cùng cấu trúc Unified Finding; xuất JSONL cùng metadata/summary; tích hợp Makefile và CI artifact. Luồng **knowledge base** xây parser, model, validation và pipeline sinh dữ liệu canonical có tính xác định; tạo SQLite FTS5 index, CLI/Make workflow, kiểm thử ranking và tài liệu vận hành. Hiện có **442 tài liệu canonical**: 409 CWE, 10 OWASP, 4 tài liệu scanner, 4 rule/alert scanner và 15 ví dụ lỗ hổng.

### Schema `unified_findings.schema.json`

Mỗi dòng trong `reports/normalized/unified-findings.jsonl` là một finding và không cho phép trường ngoài schema.

| Trường | Ý nghĩa |
| --- | --- |
| `schema_version` | Phiên bản hợp đồng dữ liệu (`1.0.0`). |
| `finding_id` | ID ngắn, ổn định của finding (`fnd_...`). |
| `fingerprint` | SHA-256 định danh chính xác một finding, phục vụ chống trùng qua nhiều lần quét. |
| `group_key` | SHA-256 để gom các finding tương đương ở mức logic. |
| `tool.{name,version,scan_type}` | Tên/version scanner và loại quét `SAST` hoặc `DAST`. |
| `scan.{run_id,pipeline_run_id,scanned_at}` | ID lần quét, ID pipeline (nếu có) và thời điểm quét ISO 8601. |
| `target.{name,version,commit_sha,base_url}` | Danh tính target: tên, phiên bản, Git commit và URL gốc; trường không phù hợp có thể là `null`. |
| `rule.{id,reference_id,name,native_severity,native_confidence}` | ID rule gốc, ID tham chiếu, tên và severity/confidence nguyên bản của scanner. |
| `title`, `description` | Tên và mô tả finding đã chuẩn hóa; có thể `null`. |
| `categories` | Các nhãn phân loại tổng quát, không trùng lặp. |
| `severity` | Mức tác động chuẩn hóa: `info/low/medium/high/critical/unknown`. |
| `confidence` | Độ chắc chắn: `false_positive/low/medium/high/confirmed/unknown`. |
| `cwe_ids`, `owasp_categories`, `wasc_ids` | Ánh xạ phân loại theo định dạng CWE, OWASP Top 10 theo năm và WASC. |
| `location` | Vị trí finding, là một trong hai kiểu `code` hoặc `http`. |
| `location` (code) | `kind=code`, `path`, dòng/cột bắt đầu và kết thúc (`start_line`, `start_column`, `end_line`, `end_column`). |
| `location` (HTTP) | `kind=http`, URL đầy đủ `uri`, đường dẫn `endpoint`, `method` và `parameter`. |
| `evidence.message` | Bằng chứng dạng thông điệp; bản v1 chủ động để `evidence=null` vì dữ liệu scanner chưa qua guardrail/redaction. |
| `data_flow[]` | Luồng taint, hoặc `null`; gồm `kind=taint`, `engine`, `source`, các `steps` trung gian và `sink`. |
| `source/steps/sink` node | Mỗi node gồm thứ tự `step_index`, `path`, `line`, `column`, đoạn `content` và `message`. |
| `solution`, `references` | Khuyến nghị xử lý và danh sách URI tham khảo. |
| `normalization.{normalizer_version,normalized_at}` | Phiên bản bộ chuẩn hóa và thời điểm chuẩn hóa. |
| `raw_sources[]` | Truy vết về dữ liệu gốc: `format`, `report_path` và `json_pointer` tới đúng record trong report. |

### Schema `knowledge_document.schema.json`

| Trường | Ý nghĩa |
| --- | --- |
| `schema_version`, `doc_id` | Phiên bản schema và ID slug duy nhất, ổn định của tài liệu. |
| `doc_type` | Loại tài liệu: `owasp_category`, `cwe`, `scanner_document`, `scanner_rule` hoặc `vulnerability_example`. |
| `title`, `aliases` | Tiêu đề chính và các tên gọi/viết tắt dùng khi tìm kiếm. |
| `summary`, `content` | Tóm tắt ngắn và nội dung đầy đủ được lập chỉ mục. |
| `identifiers.{cwe,owasp,semgrep,zap}` | Các ID liên kết chéo theo từng hệ phân loại/scanner; mỗi danh sách có thể rỗng. |
| `tags` | Từ khóa hỗ trợ phân loại và ranking. |
| `detectability.{sast,dast,manual}` | Trường tùy chọn, đánh giá khả năng phát hiện bằng từng phương pháp: `high/medium/low/unknown`. |
| `source.{name,version,raw_path,source_locator}` | Tên/version nguồn, đường dẫn file raw và vị trí/ID bên trong nguồn; `version` và `source_locator` là tùy chọn. |

## 2. Inventory Knowledge Base và trạng thái review

**Nguồn chính đã tạo:**

- OWASP Top 10:2025 tại `knowledge-base/raw/owasp/`: `A01_2025-Broken_Access_Control.md`, `A02_2025-Security_Misconfiguration.md`, `A03_2025-Software_Supply_Chain_Failures.md`, `A04_2025-Cryptographic_Failures.md`, `A05_2025-Injection.md`, `A06_2025-Insecure_Design.md`, `A07_2025-Authentication_Failures.md`, `A08_2025-Software_or_Data_Integrity_Failures.md`, `A09_2025-Security_Logging_and_Alerting_Failures.md` và `A10_2025-Mishandling_of_Exceptional_Conditions.md`.
- MITRE CWE: `knowledge-base/raw/cwe/699.csv` (399 record) và `knowledge-base/raw/cwe/1435.csv` (25 record). Có 15 record trùng và giống hoàn toàn được coalesce, tạo 409 tài liệu CWE duy nhất.
- Dữ liệu sinh ra: `knowledge-base/processed/documents.jsonl` và `manifest.json`; index cục bộ có thể tái tạo tại `knowledge-base/index/knowledge.db` và không commit.

**Cần review lại trước khi sử dụng như tri thức chuẩn:** 15 file ví dụ trong `knowledge-base/curated/examples/`; bốn file Semgrep (`finding-anatomy.md`, `rule-metadata.md`, `selected-rules/express-open-redirect.md`, `selected-rules/tainted-sql-string.md`); bốn file ZAP (`alert-anatomy.md`, `risk-confidence-evidence.md`, `selected-alerts/10038-1-csp-header-not-set.md`, `selected-alerts/10098-cross-domain-misconfiguration.md`). Cần kiểm tra lại độ chính xác kỹ thuật, mapping CWE/OWASP, nguồn trích dẫn và license/terms, đặc biệt với phần tóm tắt Semgrep/ZAP.

## 3. Cách build và tìm kiếm

Yêu cầu Python 3.11+ có SQLite JSON functions và FTS5:

```bash
make install
make kb-validate
make kb-build
make kb-search QUERY="SQL Injection" TOP_K=3
make kb-search QUERY="IDOR" DOC_TYPE=cwe
.venv/bin/python -m src.retrieval.cli search "CWE89" --top-k 2 --json
```

Ví dụ kết quả thực tế cho `SQL Injection`:

```text
Rank  Document                       Type                   Title
1     example-sql-injection-nodejs  vulnerability_example  SQL Injection in Node.js
2     cwe-89                         cwe                    CWE-89: SQL Injection
3     semgrep-rule-javascript-express-security-injection-tainted-sql-string-tainted-sql-string  scanner_rule  Semgrep Tainted SQL String Rule
```

Truy vấn `CWE89` được chuẩn hóa thành `CWE-89`; kết quả JSON đứng đầu là `doc_id: "cwe-89"`, `exact_match_rank: 0`, title `CWE-89: SQL Injection`, kèm `summary`, `aliases`, `identifiers`, `tags`, `snippet` và `bm25_score`. Ranking ưu tiên khớp chính xác identifier/title/alias, sau đó dùng weighted BM25 và `doc_id` để bảo đảm kết quả xác định. **Phiên bản Week 2 mới chỉ hỗ trợ keyword search tiếng Anh**; chưa có embedding, vector database hay semantic retrieval. Các tuần sau sẽ bổ sung **semantic search** và hợp nhất điểm semantic với exact/BM25 để tạo **hybrid search**, vẫn giữ keyword search làm nhánh truy hồi chính xác cho CWE/OWASP ID.
