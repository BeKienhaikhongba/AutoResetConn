import React from 'react';
import { X, Info, User, Star } from 'lucide-react';
import './DatabaseConfig.css'; // Reusing the modal styling

const AboutModal = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ width: '600px' }}>
        <div className="modal-header">
          <h3>
            <Info size={20} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '8px', color: 'var(--primary)' }} />
            Giới Thiệu Phần Mềm
          </h3>
          <button className="btn-icon" onClick={onClose}><X size={20} /></button>
        </div>

        <div className="modal-body" style={{ color: 'var(--text-main)', lineHeight: '1.6' }}>
          <h2 style={{ color: 'var(--primary)', marginBottom: '10px' }}>Signature Cropper Pro</h2>
          <p>Phần mềm chuyên dụng hỗ trợ số hóa, trích xuất và cắt xén chữ ký tự động từ các tài liệu PDF, Excel, Hình ảnh.</p>

          <h4 style={{ marginTop: '15px', color: 'var(--text-muted)' }}><Star size={16} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '5px' }} />Tính năng nổi bật:</h4>
          <ul style={{ marginLeft: '25px', marginTop: '8px', color: 'var(--text-muted)' }}>
            <li style={{ marginBottom: '5px' }}>Tự động nhận diện chữ ký từ file Excel.</li>
            <li style={{ marginBottom: '5px' }}>Cắt xén thủ công với độ chính xác cao.</li>
            <li style={{ marginBottom: '5px' }}>Đồng bộ trực tiếp hàng loạt vào cơ sở dữ liệu PostgreSQL.</li>
            <li>Đóng gói siêu tốc ra JSON / ZIP.</li>
          </ul>

          <div style={{ marginTop: '20px', padding: '15px', backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <h4 style={{ color: 'var(--success)' }}><User size={16} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '5px' }} /> Thông tin Tác giả</h4>
            <div style={{ marginTop: '10px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>
              {/* <p><strong>Phát triển bởi:</strong> Đội ngũ nội bộ</p> */}
              <p><strong>Phát triển bởi:</strong> Vũ Trung Kiên và các tập sự</p>
              <p style={{ marginTop: '5px' }}><strong>Phiên bản:</strong> 2026.4.19.1</p>
              <p style={{ marginTop: '5px' }}><strong>Bản quyền:</strong> © 2026 - Mọi quyền được bảo lưu.</p>
            </div>
          </div>
        </div>

        <div className="modal-footer" style={{ justifyContent: 'center' }}>
          <button className="btn btn-primary" onClick={onClose} style={{ padding: '0.5rem 2rem' }}>Đóng</button>
        </div>
      </div>
    </div>
  );
};

export default AboutModal;
