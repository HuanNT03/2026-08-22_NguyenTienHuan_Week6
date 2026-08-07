# Báo cáo Week 3 — Bổ sung Bằng chứng Cấu trúc và Security Analysis Agent

**Họ và tên:** Nguyễn Tiến Huân

**Ngày báo cáo:** 07/08/2026  
**Mục tiêu:** Nâng cấp hợp đồng Unified Findings v2.0.0 với đối tượng bằng chứng cấu trúc (`evidence`), và xây dựng Security Analysis Agent tự động phân tích lỗ hổng, truy hồi tri thức bảo mật (Knowledge Base) và gom nhóm tương quan SAST ↔ DAST.

---

## 1. Kết Quả Thực Hiện Chính

### 1.1 Chuẩn hóa Bằng chứng Cấu trúc (Evidence Enrichment - Schema v2.0.0)
- **Hợp đồng dữ liệu v2.0.0**: Thay thế v1.0.0, bắt buộc mỗi finding phải chứa cấu trúc `evidence` hợp lệ (`kind`, `code_evidence`, `http_evidence`, `quality`, `provenance`).
- **Nâng cao ngữ cảnh mã nguồn**: Tự động đọc và bổ sung tới 5 dòng ngữ cảnh trước (`context_before`) và sau (`context_after`) đoạn code bị lỗi từ target repository.
- **Bằng chứng HTTP & Phân loại chất lượng**: Lưu trữ đầy đủ request excerpt, attack payload, context note cho DAST; phân loại mức độ tin cậy bằng chứng (`direct`, `enriched`, `inferred`, `none`).

### 1.2 Triển khai Security Analysis Agent
- **Giao thức 3 Giai đoạn (3-Phase Pipeline)**:
  1. *Phase 1 (Pre-Grouping & Correlation)*: Gom nhóm findings theo `group_key`, CWE Intersection, Title Similarity và Parameter-to-DataFlow Matching. Xác định quan hệ tương quan SAST ↔ DAST (`sast_dast_suspected`).
  2. *Phase 2 (Agentic Analysis Loop)*: Vòng lặp phân tích cô lập per-group. Tự động truy hồi tri thức per-CWE từ SQLite FTS5 KB và thực hiện làm sạch dữ liệu nhạy cảm (PII/secrets redaction) trước khi gọi LLM API.
  3. *Phase 3 (Post-Processing & 100% Coverage)*: Xác minh 100% fingerprints đầu vào đều có kết quả phân tích. Tự động sinh fallback entry với `analysis_status = "error"` nếu gọi LLM fail sau max retries.
- **Hợp đồng đầu ra Schema `security_analysis_report.schema.json`**: Xuất file JSONL (1 entry / 1 fingerprint, chứa `analysis_group_id` cho UI) tại `reports/analyzed/` kèm đề xuất kiểm thử an toàn dạng dữ liệu (`proposed_test_request`).
- **Tích hợp CLI & Makefile**: Cung cấp các lệnh `make agent-analyze FINDINGS=...`, `make agent-test` (34/34 test cases passed) và `make agent-lint`.

---

## 2. Thống Kê & Kết Quả Kiểm Thử

- **Bộ dữ liệu chuẩn hóa v2**: 165 findings (37 SAST Semgrep, 87 SAST CodeQL, 41 DAST ZAP) được gom thành 37 Analysis Groups, phát hiện 2 nhóm tương quan SAST ↔ DAST chính (SQL Injection CWE-89 & Open Redirect CWE-601).
- **Kiểm thử tự động**:
  - `make agent-test`: **34/34 passed** (Schema, Correlator, Grouper, Redaction, Analyzer Mock, Orchestrator, Edge Cases).
  - `make test`: **115/115 passed** (Regression check cho toàn bộ pipeline).
  - `make kb-test`: **105/105 passed** (Knowledge Base search).
  - `make agent-lint`: **All checks passed!**
