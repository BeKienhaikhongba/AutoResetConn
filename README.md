# AutoResetConn - Auto Reset DB Tool

Công cụ quản lý và tự động reset kết nối database PostgreSQL (giao diện phong cách Dark Slate Modern).

## 🚀 Cách chạy chương trình

Để chạy chương trình trực tiếp từ mã nguồn Python, hãy mở PowerShell hoặc terminal tại thư mục dự án và chạy lệnh sau:

```powershell
$env:PYTHONUTF8=1; uv run --with requests --with psycopg2-binary --with cryptography AutoResetConn.py
```

*(Lưu ý: Dự án sử dụng `uv` để tự động quản lý các thư viện phụ thuộc và môi trường ảo.)*

---

## 📦 Cơ chế tự động cập nhật (Auto-Updater)

Ứng dụng tích hợp cơ chế tự động cập nhật. Khi khởi động, client sẽ đối chiếu phiên bản hiện tại trong file `version_local.txt` với file `version.txt` trên GitHub.
Nếu có sự khác biệt về phiên bản:
1. Client sẽ tự động tải phiên bản mới nhất của file core (`core/AutoResetConn.py`) từ GitHub về ghi đè vào thư mục local.
2. Cập nhật lại file `version_local.txt` nội bộ để khớp với server.

### 🛠️ Quy tắc định dạng phiên bản:
Định dạng phiên bản sử dụng: `YYYY.MM.DD.x`
- `YYYY.MM.DD`: Ngày thực hiện phát hành (Năm.Tháng.Ngày).
- `x`: Số thứ tự của bản build trong ngày đó (bắt đầu từ `1`).
Ví dụ: Bản build đầu tiên trong ngày 30/06/2026 sẽ có số phiên bản là `2026.06.30.1`. Bản build tiếp theo cùng ngày sẽ là `2026.06.30.2`.

---

## ⚡ Quy trình cập nhật bản mới lên Git

### Cách 1: Sử dụng Script tự động (Khuyên dùng)

Dự án đã tích hợp sẵn công cụ `release.py` giúp bạn tự động hóa toàn bộ quá trình tăng số phiên bản và đẩy lên Git.

Chỉ cần chạy lệnh sau tại terminal:
```powershell
python release.py
```

**Script `release.py` sẽ tự động:**
1. Đọc phiên bản hiện tại từ `version.txt`.
2. Kiểm tra nếu cùng ngày hôm nay, nó sẽ tự động tăng chỉ số chỉ lần build `x` lên 1 (Ví dụ: `2026.06.30.1` -> `2026.06.30.2`). Nếu bước sang ngày mới, nó sẽ tự khởi động lại về `.1` (Ví dụ: `2026.07.01.1`).
3. Ghi đè phiên bản mới vào cả `version.txt` và `version_local.txt`.
4. Tự động chạy chuỗi lệnh `git add`, `git commit` và `git push` để đẩy code lên GitHub.
*(Nếu máy chưa cấu hình lệnh `git` trong biến môi trường PATH, script sẽ hiển thị chuỗi lệnh thủ công để bạn dễ dàng sao chép chạy bằng tay).*z

---

### Cách 2: Thực hiện thủ công

Nếu muốn tự làm bằng tay, bạn có thể thực hiện theo quy trình sau:

1. Chỉnh sửa code ở file chính `AutoResetConn.py` và file core `core/AutoResetConn.py`.
2. Mở file `version.txt` và `version_local.txt` lên, chỉnh sửa thủ công số phiên bản theo quy tắc `YYYY.MM.DD.x` (Ví dụ: `2026.06.30.1`).
3. Mở Git terminal và chạy các lệnh sau để commit và push lên GitHub:
   ```bash
   git add version.txt version_local.txt core/AutoResetConn.py AutoResetConn.py
   git commit -m "Release v2026.7.2.1"
   git push
   ```