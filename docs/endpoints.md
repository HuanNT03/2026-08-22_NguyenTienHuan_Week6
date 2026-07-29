# Juice Shop endpoints — Week 1

Các endpoint dưới đây được đối chiếu từ source đúng commit
`f915bddd82790d0f3018902d36ae9b4241a5f51f`. Trạng thái DAST vẫn để chưa xác minh vì ZAP
chưa thể chạy khi Docker daemon không khả dụng. Không suy đoán endpoint từ phiên bản khác.

| Method | Path | Chức năng | Authentication | Nguồn xác minh | DAST reachable |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/Products` | Liệt kê sản phẩm | Không | `test/api/product.test.ts` | Chưa xác minh |
| GET | `/rest/products/search?q=<query>` | Tìm kiếm sản phẩm | Không | `server.ts`, `test/api/search.test.ts` | Chưa xác minh |
| POST | `/rest/user/login` | Xác thực bằng thông tin đăng nhập | Không (endpoint cấp token) | `server.ts`, `test/api/login.test.ts` | Chưa xác minh |
| GET | `/rest/user/whoami` | Trả về user tương ứng với request/token hiện tại | Token tùy trạng thái request | `server.ts`, `routes/whoami.ts` | Chưa xác minh |

Sau khi scan, review `reports/raw/zap.json`; raw output không được xem là curated documentation
cho đến khi người thực hiện đối chiếu source hoặc request thực tế.
