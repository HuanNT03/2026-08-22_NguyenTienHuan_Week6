# Ground truth

Ground truth là pipeline đánh giá độc lập với scope SAST/DAST. Việc loại
`target-app/juice-shop/data/static/codefixes/` khỏi Semgrep và CodeQL không xóa hoặc thay đổi
nguồn này.

## Nguồn và mục đích

| Pipeline | Nguồn | Mục đích |
| --- | --- | --- |
| SAST runtime | `routes/`, `lib/`, `models/`, runtime data/config, `frontend/src/` | So khớp với bề mặt HTTP của DAST |
| Ground truth generated | `data/static/codefixes/` kết hợp `challenges.yml` và vuln-code-snippet | Sinh candidate label để đánh giá agent |
| Ground truth curated | Candidate đã được người review | Tính precision, recall và benchmark |

`generated/` dành cho output có thể tái tạo từ target đã pin. `curated/` chỉ nhận record đã được
review thủ công; không tự xem snippet hoặc scanner finding là đáp án đúng. Parser cho
`challenges.yml`/vuln-code-snippet chưa được triển khai trong thay đổi scope này.

## Quy tắc an toàn

- Ghi provenance gồm target tag, commit và source location cho mỗi record.
- Không đưa generated label chưa review vào metric chính thức.
- Không trộn finding SCA/dependency với ground truth cho overlap SAST/DAST.
- Không sửa source Juice Shop để tạo ground truth; target vẫn được pin và read-only khi scan.
