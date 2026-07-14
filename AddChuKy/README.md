# Signature Cropper Pro

## 📖 Giới Thiệu
**Signature Cropper Pro** là một công cụ thông minh được thiết kế đặc biệt để hỗ trợ trích xuất, cắt xén và quản lý chữ ký từ các loại tài liệu (PDF, JPG, PNG, Excel). Phần mềm giúp số hóa quy trình thu thập chữ ký của nhân viên một cách tự động, nhanh chóng và chính xác.

## ✨ Tính Năng Chính
- **Đọc Đa Định Dạng**: Hỗ trợ kéo thả trực tiếp file ảnh, PDF hoặc danh sách Excel.
- **Tự Động Trích Xuất**: Tự động quét và trích xuất hàng loạt chữ ký có sẵn trong file Excel.
- **Cắt Chữ Ký Thủ Công**: Giao diện Crop linh hoạt, tự động gợi ý tên/mã nhân viên dựa trên nhận dạng ký tự (OCR) hoặc dữ liệu nhập vào.
- **Đồng Bộ Database**: Kết nối trực tiếp với PostgreSQL, đẩy hàng loạt chữ ký đã xử lý (định dạng Base64) vào hệ thống chỉ với 1 click.
- **Xuất Dữ Liệu Ngoại Tuyến**: Hỗ trợ đóng gói tất cả hình ảnh thành file nén JSON/ZIP.

## 👤 Tác Giả & Bản Quyền
- **Phát triển bởi**: Đội ngũ phát triển phần mềm nội bộ.
- **Phiên bản**: Quản lý version tự động (Auto-versioning) định dạng `yyyy.m.d.x`.
- **Bản quyền**: © 2026 - Mọi quyền được bảo lưu.

---
## 🚀 Hướng Dẫn Chạy & Cập Nhật Phiên Bản

**1. Chạy phiên bản phát triển (Development):**
```bash
npm run dev
```

**2. Đóng gói & Tự động cập nhật phiên bản mới (Release):**
Khi bạn muốn xuất bản một bản build mới (file thực thi), chỉ cần chạy lệnh sau:
```bash
npm run release
```
*Lưu ý: Lệnh này sẽ tự động chạy script `update-version.js` để tăng số version, build giao diện mới nhất, và đóng gói ứng dụng thành file chạy độc lập cho Windows.*