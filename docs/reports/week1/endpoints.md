# Juice Shop endpoints — Week 1

Các endpoint dưới đây được đối chiếu từ source đúng commit
`f915bddd82790d0f3018902d36ae9b4241a5f51f`. Danh sách đã được review lại sau khi giới hạn
SAST scope; không endpoint nào bắt nguồn từ `.github/` hoặc `data/static/codefixes/`.

| Method | Path | Chức năng | Authentication | Nguồn xác minh | DAST reachable |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/Products` | Liệt kê sản phẩm | Không | `server.ts` (Sequelize Finale resource) | Chưa xác minh |
| GET | `/rest/products/search?q=<query>` | Tìm kiếm sản phẩm | Không | `server.ts`, `routes/search.ts` | Chưa xác minh |
| POST | `/rest/user/login` | Xác thực bằng thông tin đăng nhập | Không (endpoint cấp token) | `server.ts`, `routes/login.ts` | Chưa xác minh |
| GET | `/rest/user/whoami` | Trả về user tương ứng với request/token hiện tại | Token tùy trạng thái request | `server.ts`, `routes/whoami.ts` | Chưa xác minh |

Sau khi scan, review `reports/raw/zap-endpoints.txt` để có inventory URL đầy đủ mà ZAP export và
`reports/raw/zap-site-tree.yaml` để xem cấu trúc site tree. Đối chiếu chúng với
`reports/raw/zap.json`, source hoặc request thực tế trước khi đánh dấu endpoint là đã xác minh.
Ba file đều là raw output không đáng tin cậy, có thể chứa query value và không được đưa trực tiếp
vào prompt/log. Validator hiện yêu cầu inventory/site tree không rỗng và chỉ chứa exact origin
`http://juice-shop:3000`; phát hiện origin khác phải được xử lý như scope regression.
