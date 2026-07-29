# Juice Shop endpoints — Week 1

Chưa có endpoint nào được ghi nhận là đã xác minh trong tài liệu này. Bảng chỉ được cập nhật từ
source đúng commit `f915bddd82790d0f3018902d36ae9b4241a5f51f`, output ZAP spider, hoặc network
request được người review kiểm tra thủ công. Không suy đoán endpoint từ phiên bản Juice Shop khác.

| Method | Path | Chức năng | Authentication | Nguồn xác minh | DAST reachable |
| --- | --- | --- | --- | --- | --- |
| — | — | Chưa xác minh | — | Chạy target/source review hoặc `make dast` | — |

Sau khi scan, review `reports/raw/zap.json`; raw output không được xem là curated documentation
cho đến khi người thực hiện đối chiếu source hoặc request thực tế.
