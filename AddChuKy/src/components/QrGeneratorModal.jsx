import React, { useState, useRef } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { X, Download, QrCode } from 'lucide-react';
import './QrGeneratorModal.css';

const QrGeneratorModal = ({ isOpen, onClose }) => {
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const qrRef = useRef(null);

  if (!isOpen) return null;

  // Xử lý tạo chuỗi JSON theo chuẩn của tool cũ
  const qrData = JSON.stringify({
    URL: url.trim(),
    TenBenhVien: name.trim()
  });

  const handleDownload = () => {
    if (!url.trim() || !name.trim()) return;

    setIsSubmitting(true);

    try {
      // Vì đang dùng QRCodeSVG, ta cần chuyển SVG sang Canvas để tải ảnh PNG
      const svg = qrRef.current.querySelector('svg');
      const svgData = new XMLSerializer().serializeToString(svg);
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      const img = new Image();

      img.onload = () => {
        // Thiết lập kích thước canvas bằng với SVG, cộng thêm viền (padding)
        const padding = 20;
        canvas.width = img.width + padding * 2;
        canvas.height = img.height + padding * 2;

        // Vẽ nền trắng
        ctx.fillStyle = '#FFFFFF';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        // Vẽ SVG lên canvas
        ctx.drawImage(img, padding, padding);

        // Tải xuống PNG
        const pngFile = canvas.toDataURL('image/png');
        const downloadLink = document.createElement('a');

        // Tạo tên file an toàn (bỏ ký tự đặc biệt)
        const safeName = name.replace(/[^a-zA-Z0-9 _]/g, '').trim().replace(/\s+/g, '_');
        downloadLink.download = `QR_${safeName || 'Code'}.png`;
        downloadLink.href = pngFile;
        downloadLink.click();

        setIsSubmitting(false);
      };

      // Chuyển đổi SVG thành base64 để Image có thể load
      img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));

    } catch (error) {
      console.error('Lỗi khi tải mã QR:', error);
      alert('Đã có lỗi xảy ra khi lưu mã QR.');
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    // Reset form khi đóng
    setUrl('');
    setName('');
    onClose();
  };

  const isValid = url.trim().length > 0 && name.trim().length > 0;

  return (
    <div className="qr-modal-overlay">
      <div className="qr-modal-content">
        <div className="qr-modal-header">
          <h2><QrCode size={24} /> Tạo Mã QR</h2>
          <button className="close-btn" onClick={handleClose} title="Đóng">
            <X size={20} />
          </button>
        </div>

        <div className="qr-modal-body">
          <div className="form-group">
            <label htmlFor="qr-url">URL <span style={{ color: 'red' }}>*</span></label>
            <input
              id="qr-url"
              type="text"
              placeholder="Nhập URL (ví dụ: http://benhvien.io:8000)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              autoFocus
            />
            {url.trim() === '' && <p className="form-error">Bắt buộc nhập URL hợp lệ</p>}
          </div>

          <div className="form-group">
            <label htmlFor="qr-name">Tên Bệnh viện/Tổ chức <span style={{ color: 'red' }}>*</span></label>
            <input
              id="qr-name"
              type="text"
              placeholder="Nhập tên (ví dụ: Bệnh viện X)"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            {name.trim() === '' && <p className="form-error">Bắt buộc nhập tên</p>}
          </div>

          <div className="qr-preview-container" ref={qrRef}>
            {isValid ? (
              <div className="qr-code-wrapper">
                <QRCodeSVG
                  value={qrData}
                  size={200}
                  level="M" // Mức độ sửa lỗi Medium (tốt cho dữ liệu dài như JSON)
                  includeMargin={false}
                />
              </div>
            ) : (
              <div className="qr-placeholder">
                <QrCode size={48} color="#d1d5db" style={{ marginBottom: '10px' }} />
                <p>Nhập đủ URL và Tên để xem trước mã QR</p>
              </div>
            )}
          </div>
        </div>

        <div className="qr-modal-footer">
          <button className="qr-btn qr-btn-cancel" onClick={handleClose}>
            Hủy
          </button>
          <button
            className="qr-btn qr-btn-save"
            onClick={handleDownload}
            disabled={!isValid || isSubmitting}
          >
            <Download size={18} /> {isSubmitting ? 'Đang lưu...' : 'Lưu QR Code'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default QrGeneratorModal;
