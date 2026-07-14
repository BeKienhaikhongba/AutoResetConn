import express from 'express';
import cors from 'cors';
import pkg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Phục vụ giao diện Frontend đã được build
app.use(express.static(path.join(__dirname, 'dist')));

app.post('/api/test-db', async (req, res) => {
  const { config } = req.body;
  if (!config || !config.host || !config.database || !config.user) {
    return res.status(400).json({ success: false, error: 'Thiếu thông tin cấu hình' });
  }
  const pool = new Pool({
    host: config.host,
    port: parseInt(config.port) || 5432,
    database: config.database,
    user: config.user,
    password: config.password,
  });
  try {
    const client = await pool.connect();
    client.release();
    res.json({ success: true, message: 'Kết nối thành công!' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  } finally {
    await pool.end();
  }
});

app.post('/api/sync-db', async (req, res) => {
  const { config, signatures } = req.body;
  
  if (!config || !config.host || !config.database || !config.user || !signatures) {
    return res.status(400).json({ success: false, error: 'Thiếu thông tin cấu hình hoặc dữ liệu chữ ký.' });
  }

  const pool = new Pool({
    host: config.host,
    port: parseInt(config.port) || 5432,
    database: config.database,
    user: config.user,
    password: config.password,
  });

  const logs = [];
  let success_count = 0;
  let failed_count = 0;

  try {
    for (const sig of signatures) {
      const name = sig.empCode;
      const b64_data = sig.base64_data;

      if (!name) {
         failed_count++;
         logs.push(`WARNING: [BỎ QUA] Không có mã nhân viên/tên đăng nhập.`);
         continue;
      }

      // Check if exists
      const resSelect = await pool.query("SELECT nhanvienid FROM tb_nhanvien WHERE nhanviencode = $1", [name]);
      if (resSelect.rows.length === 0) {
        failed_count++;
        logs.push(`WARNING: [KHÔNG TÌM THẤY] ${name}: Không tồn tại trong DB.`);
        continue;
      }

      const nhanvienid = resSelect.rows[0].nhanvienid;
      
      if (typeof b64_data !== 'string') {
        failed_count++;
        logs.push(`ERROR: [LỖI DỮ LIỆU] ${name}: 'base64_data' không phải là chuỗi.`);
        continue;
      }

      let imageBuffer;
      try {
        imageBuffer = Buffer.from(b64_data, 'base64');
      } catch (b64e) {
        failed_count++;
        logs.push(`ERROR: [LỖI GIẢI MÃ BASE64] ${name}: ${b64e.message}`);
        continue;
      }

      try {
        await pool.query(`
            UPDATE tb_nhanvien
            SET imagedatasignscan = $1, isdungchukyao = 1
            WHERE nhanvienid = $2
        `, [imageBuffer, nhanvienid]);

        success_count++;
        logs.push(`INFO: [OK] ${name} (ID: ${nhanvienid}) đã cập nhật chữ ký.`);
      } catch (dbErr) {
        failed_count++;
        logs.push(`ERROR: [LỖI DB] ${name}: ${dbErr.message}`);
      }
    }

    res.json({ success: true, success_count, failed_count, logs });
  } catch (err) {
    logs.push(`ERROR: Lỗi hệ thống: ${err.message}`);
    res.status(500).json({ success: false, logs, error: err.message });
  } finally {
    await pool.end();
  }
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`);
});
