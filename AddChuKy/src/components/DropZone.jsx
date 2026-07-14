import React, { useCallback, useRef } from 'react';
import { UploadCloud } from 'lucide-react';
import './DropZone.css';

const DropZone = ({ onUpload, isProcessing }) => {
  const fileInputRef = useRef(null);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const files = Array.from(e.dataTransfer.files);
      const hasExcel = files.some(f => f.name.match(/\.(xlsx|xls)$/i));
      const hasImageOrPdf = files.some(f => f.type === 'application/pdf' || f.type.startsWith('image/'));
      
      onUpload(e.dataTransfer.files);

      // Mở cửa sổ chọn file đồng bộ ngay lập tức để không bị trình duyệt chặn
      if (hasExcel && !hasImageOrPdf) {
         if (fileInputRef.current) fileInputRef.current.click();
      }
    }
  }, [onUpload]);

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  const handleChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      const files = Array.from(e.target.files);
      const hasExcel = files.some(f => f.name.match(/\.(xlsx|xls)$/i));
      const hasImageOrPdf = files.some(f => f.type === 'application/pdf' || f.type.startsWith('image/'));
      
      onUpload(e.target.files);
      
      if (hasExcel && !hasImageOrPdf) {
         if (fileInputRef.current) fileInputRef.current.click();
      }
      
      e.target.value = null; // Reset để có thể chọn lại file cũ nếu muốn
    }
  };

  return (
    <div 
      className="dropzone-container"
      onDrop={handleDrop}
      onDragOver={handleDragOver}
    >
      <div className="dropzone-content">
        <UploadCloud size={64} className="upload-icon" />
        <h2>{isProcessing ? "Đang xử lý..." : "Kéo thả file vào đây"}</h2>
        <p>Hỗ trợ: PDF, JPG, PNG, XLS, XLSX</p>
        <label className="btn btn-primary upload-btn">
          Chọn File
          <input 
            type="file" 
            multiple 
            accept=".pdf,image/*,.xlsx,.xls" 
            onChange={handleChange} 
            disabled={isProcessing}
            ref={fileInputRef}
          />
        </label>
      </div>
    </div>
  );
};

export default DropZone;
