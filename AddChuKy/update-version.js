import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const versionFilePath = path.join(__dirname, 'version.json');

// Lấy ngày hiện tại
const today = new Date();
const yyyy = today.getFullYear();
const m = today.getMonth() + 1; // getMonth trả về từ 0-11
const d = today.getDate(); // Ngày không có số 0 ở đầu

const datePrefix = `${yyyy}.${m}.${d}`;

// Đọc version cũ
let oldVersion = '';
try {
  if (fs.existsSync(versionFilePath)) {
    const rawData = fs.readFileSync(versionFilePath);
    const parsed = JSON.parse(rawData);
    oldVersion = parsed.version || '';
  }
} catch (e) {
  console.log('Không đọc được version cũ, tạo mới.');
}

let newVersion = '';

// Kiểm tra xem version cũ có bắt đầu bằng tiền tố ngày hôm nay không
if (oldVersion.startsWith(datePrefix + '.')) {
  // Trích xuất số x ở cuối
  const parts = oldVersion.split('.');
  const x = parseInt(parts[parts.length - 1], 10);
  newVersion = `${datePrefix}.${x + 1}`;
} else {
  // Ngày mới, reset đuôi x về 1
  newVersion = `${datePrefix}.1`;
}

// Lưu lại file version.json
fs.writeFileSync(versionFilePath, JSON.stringify({ version: newVersion }, null, 2));

console.log(`[Auto Versioning] Đã cập nhật phiên bản thành: ${newVersion}`);
