# Báo cáo Kỹ thuật Tuần 5: Kiến trúc Dynamic Ingestion & Two-Stage Hybrid Retrieval (RRF + Pure MMR)

## 1. Tổng quan hệ thống Knowledge Retrieval

Hệ thống Knowledge Base & Retrieval của **Project Sentinel** được nâng cấp toàn diện từ hệ thống đơn giản sang **Kiến trúc Truy hồi Lai 2 Giai đoạn (Two-Stage Hybrid Search)** kết hợp **Dynamic Data Ingestion** tự động nạp 100% tài liệu thô trong repository mà không cần hardcode số lượng hay cấu trúc tĩnh.

Hệ thống quản lý **1.832 tài liệu bảo mật chuẩn hóa** (Canonical Knowledge Documents) bao gồm:
- **CWE Views**: 409 tài liệu từ CWE Research Concepts (699) và Top 25 (1435).
- **OWASP Top 10 Multi-version**: Các ấn bản OWASP Top 10 năm 2025, 2021, và 2017.
- **OWASP ASVS v5.0.0**: 342 yêu cầu kiểm thử xác thực ứng dụng bảo mật (Application Security Verification Standard).
- **OWASP Security Cheat Sheets**: 62 tài liệu hướng dẫn phòng thủ chuyên sâu (AI Agent, Docker, REST, Node.js, Mass Assignment, v.v.).
- **Semgrep Security Rules**: 100+ quy tắc phát hiện lỗ hổng SAST (Node.js, Express, JavaScript, Postgres, JWT, v.v.).
- **OWASP ZAP Alerts & Docker Guides**: 30+ định nghĩa cảnh báo DAST và hướng dẫn tự động hóa kiểm thử web an toàn.
- **CodeQL & Semgrep Guides**: Tài liệu tra cứu Data Flow & Taint Analysis.
- **Curated Vulnerability Examples**: 20 kịch bản mẫu đối sánh mã nguồn thực tế (Node.js/Express) bao phủ toàn bộ 10 danh mục OWASP 2025.

---

## 2. Quy trình & Kiến trúc Hybrid Search 2 Giai đoạn

Sơ đồ quy trình xử lý truy vấn:

```
[Truy vấn người dùng / Agent Finding]
              │
              ▼
    [Smart Query Parser] ────► Tách liên từ (và, hoặc, and, or, dấu phẩy)
              │               Chuẩn hóa định danh (CWE-89, A05:2025)
              │
    ┌─────────┴─────────┐
    ▼                   ▼
[Stage 1A: Sparse]   [Stage 1B: Dense]
  SQLite FTS5          Qdrant Embedded
  BM25 Ranking         Cosine Similarity
  (Top 20 Candidates)  (Top 20 Candidates + Vectors)
    └─────────┬─────────┘
              ▼
  [Stage 1 Fusion: RRF]
  Reciprocal Rank Fusion Score: w1/(k + rank_sparse) + w2/(k + rank_dense)
              │
              ▼
  [Stage 2 Reranking: Pure MMR]
  Maximal Marginal Relevance: λ * Rel(d_i) - (1-λ) * max Sim(v_i, v_selected)
  (Loại bỏ Semantic Clumping, tối ưu hóa đa dạng hóa chủng loại tài liệu)
              │
              ▼
  [Hydration & Output] ──► Top K Knowledge Documents (Snippet, Title, Identifiers, Metadata)
```

### Giai đoạn 1: Truy hồi ứng viên & Kết hợp Xếp hạng (RRF Fusion)
1. **Sparse Search (SQLite FTS5 + BM25)**:
   - Truy vấn được chuẩn hóa qua `build_smart_match_expression`.
   - Tìm kiếm chính xác trên các trường `identifiers_text`, `title`, `aliases_text`, `tags_text`, `summary`, `content`.
   - Lấy danh sách Top 20 ứng viên cùng điểm BM25.
2. **Dense Search (Qdrant Vector Store + Cosine)**:
   - Truy vấn được chuyển đổi thành vector embedding 1536 chiều qua `EmbeddingClient`.
   - Tìm kiếm lân cận gần nhất (Approximate Nearest Neighbors) dựa trên độ đo Cosine.
   - Lấy danh sách Top 20 ứng viên cùng vector embedding và metadata payload.
3. **Reciprocal Rank Fusion (RRF)**:
   - Kết hợp hai bảng xếp hạng không phụ thuộc vào thang điểm tuyệt đối:
   $$\text{RRF Score}(d) = \frac{w_{\text{sparse}}}{k + \text{Rank}_{\text{sparse}}(d)} + \frac{w_{\text{dense}}}{k + \text{Rank}_{\text{dense}}(d)}$$
   - Với hằng số $k = 60$. Tài liệu xuất hiện ở thứ hạng cao trên cả hai kênh sẽ có điểm RRF vượt trội.

### Giai đoạn 2: Tái sắp xếp Đa dạng hóa (Pure MMR Diversity Reranking)
Khi điểm tương đồng ngữ nghĩa giữa các tài liệu quá gần nhau (Semantic Clumping) hoặc có nhiều quy tắc scanner trùng lặp nội dung, giải thuật **Maximal Marginal Relevance (MMR)** được áp dụng:
$$\text{MMR}(d_i) = \lambda \cdot \text{Sim}(d_i, Q) - (1 - \lambda) \max_{d_j \in S} \text{CosineSim}(v_i, v_j)$$
- **$\lambda = 0.7$**: Cân bằng giữa độ phù hợp truy vấn ($\text{Sim}(d_i, Q)$) và sự khác biệt đối với các tài liệu đã chọn ($S$).
- Giúp kết quả trả về không chỉ toàn quy tắc Semgrep hoặc toàn định nghĩa CWE, mà cung cấp một tập phong phú gồm: CWE Taxonomy + OWASP Standard + Vulnerability Code Example + Mitigation Cheat Sheet.

---

## 3. Cấu trúc Database & Metadata Schema

### A. Cơ sở dữ liệu Từ khóa: SQLite FTS5 (`knowledge-base/index/knowledge.db`)

Bảng `documents` và Virtual Table `knowledge_fts` (External-content FTS5):

| Trường (Column) | Kiểu dữ liệu | Mô tả chi tiết |
| :--- | :--- | :--- |
| `rowid` | `INTEGER PRIMARY KEY` | Khóa chính nội bộ đồng bộ giữa SQLite Table và FTS Index |
| `doc_id` | `TEXT NOT NULL UNIQUE` | Định danh chuẩn hóa duy nhất (slug) của tài liệu |
| `doc_type` | `TEXT NOT NULL` | Chủng loại (`cwe`, `owasp_category`, `asvs_requirement`, `cheatsheet`, `scanner_rule`, `scanner_document`, `vulnerability_example`) |
| `title` | `TEXT NOT NULL` | Tiêu đề chính xác của tài liệu |
| `aliases_json` | `TEXT NOT NULL` | JSON mảng các tên gọi thay thế, viết tắt (ví dụ: `["SQLi", "SQL Injection"]`) |
| `aliases_text` | `TEXT NOT NULL` | Văn bản nối từ aliases dùng cho chỉ mục FTS |
| `identifiers_json` | `TEXT NOT NULL` | JSON object chứa định danh bảo mật (`cwe`, `owasp`, `semgrep`, `zap`) |
| `identifiers_text` | `TEXT NOT NULL` | Văn bản nối tất cả định danh dùng cho exact lookup |
| `tags_json` | `TEXT NOT NULL` | JSON mảng các nhãn phân loại (technology, risk, severity, v.v.) |
| `tags_text` | `TEXT NOT NULL` | Văn bản nối các nhãn phân loại cho chỉ mục FTS |
| `summary` | `TEXT NOT NULL` | Tóm tắt kỹ thuật ngắn gọn về lỗ hổng/hướng dẫn |
| `content` | `TEXT NOT NULL` | Nội dung chi tiết đầy đủ (Markdown/Plain text) |
| `source_json` | `TEXT NOT NULL` | Thông tin nguồn gốc, version, raw file path, source locator |

### B. Cơ sở dữ liệu Vector: Qdrant Embedded (`knowledge-base/index/qdrant_storage`)

Collection: `sentinel_knowledge`  
Cấu hình Vector: `size=1536`, `distance=Cosine`

Cấu trúc **Point Payload** được lưu trữ trong Qdrant:
```json
{
  "id": "uuid5(doc_id)",
  "vector": [0.0124, -0.0431, ..., 0.0892],
  "payload": {
    "doc_id": "cwe-89",
    "doc_type": "cwe",
    "title": "CWE-89: SQL Injection",
    "summary": "The product constructs all or part of an SQL command using externally-influenced input...",
    "identifiers": {
      "cwe": ["CWE-89"],
      "owasp": ["A03:2021", "A05:2025"],
      "semgrep": [],
      "zap": []
    },
    "tags": ["sql", "injection", "database", "rce"],
    "source": {
      "name": "CWE Research Concepts",
      "version": "4.14",
      "raw_path": "knowledge-base/raw/cwe/699.csv",
      "source_locator": "89"
    }
  }
}
```

---

## 4. Hướng dẫn vận hành qua Makefile

Hệ thống cung cấp các lệnh Makefile chuyên dụng cho từng chế độ truy hồi:

### 1. Tìm kiếm Hybrid 2 Giai đoạn (Mặc định)
```bash
make kb-search QUERY="SQL Injection"
# hoặc
make kb-search-hybrid QUERY="cwe 89 hoặc sql injection"
```

### 2. Tìm kiếm Từ khóa Thông minh (Multi-Keyword Sparse BM25)
Hỗ trợ liên từ tiếng Việt (`và`, `hoặc`, `hay`, dấu phẩy) và tiếng Anh (`and`, `or`, `with`):
```bash
make kb-search-keyword QUERY="cwe 89 và owasp a05:2025"
make kb-search-keyword QUERY="XSS, CSRF, IDOR"
```

### 3. Tìm kiếm Ngữ nghĩa Dense Vector (Semantic Similarity)
```bash
make kb-search-semantic QUERY="unvalidated user input database query execution"
```

### 4. Build & Kiểm thử toàn bộ Knowledge Base
```bash
make kb-validate    # Kiểm tra tính hợp lệ của 1.832 tài liệu thô
make kb-build       # Sinh canonical documents.jsonl, SQLite FTS5 và Qdrant Vector Index
make kb-test        # Chạy 118 unit & integration tests cho toàn bộ hệ thống retrieval
make kb-lint        # Kiểm tra chuẩn coding convention & Ruff linter
```

---

## 5. Kết luận & Đánh giá

1. **Khả năng mở rộng Dynamic Ingestion**: Hệ thống tự động nhận diện tài liệu mới thêm vào `knowledge-base/raw/` (như cheat sheets, scanner rules, hay ASVS) mà không làm vỡ data contract hay yêu cầu sửa code logic.
2. **Khả năng Recall & Precision**: Sự phối hợp giữa Smart Multi-Keyword Parser (xử lý chính xác định danh CWE/OWASP) và Dense Semantic Vector Search (xử lý mô tả tự nhiên) mang lại tỷ lệ truy hồi tri thức tối ưu cho Security Analysis Agent trong Week 3 và các tuần tiếp theo.
