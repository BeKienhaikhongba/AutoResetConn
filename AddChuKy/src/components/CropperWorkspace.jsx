import React, { useState, useRef, useEffect } from 'react';
import ReactCrop from 'react-image-crop';
import { processCanvasBackground } from '../utils/backgroundRemoval';
import { isValidName } from '../utils/stringUtils';
import { Crop, Save, ChevronLeft, ChevronRight, ScanText, Loader2, X } from 'lucide-react';
import Tesseract from 'tesseract.js';
import './CropperWorkspace.css';

const CropperWorkspace = ({ imageUrl, onSave, metadataPreview, onNextImage, onPrevImage, currentIndex, totalImages }) => {
  const [crop, setCrop] = useState();
  const [completedCrop, setCompletedCrop] = useState(null);
  const [scannedName, setScannedName] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const imgRef = useRef(null);

  // Reset state when image changes
  useEffect(() => {
    setCrop(undefined);
    setCompletedCrop(null);
    setScannedName("");
  }, [imageUrl]);

  const onImageLoad = (e) => {
    const img = e.target;
    // Auto-crop bounding box
    const canvas = document.createElement('canvas');
    canvas.width = img.naturalWidth;
    canvas.height = img.naturalHeight;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    
    try {
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const data = imageData.data;
      
      let minX = canvas.width, minY = canvas.height, maxX = 0, maxY = 0;
      let hasInk = false;
      
      for (let y = 0; y < canvas.height; y++) {
        for (let x = 0; x < canvas.width; x++) {
          const idx = (y * canvas.width + x) * 4;
          const r = data[idx], g = data[idx+1], b = data[idx+2], a = data[idx+3];
          
          if (a > 10 && (r < 240 || g < 240 || b < 240)) {
            if (x < minX) minX = x;
            if (x > maxX) maxX = x;
            if (y < minY) minY = y;
            if (y > maxY) maxY = y;
            hasInk = true;
          }
        }
      }
      
      if (hasInk) {
        const padX = canvas.width * 0.02;
        const padY = canvas.height * 0.02;
        
        const finalMinX = Math.max(0, minX - padX);
        const finalMinY = Math.max(0, minY - padY);
        const finalMaxX = Math.min(canvas.width, maxX + padX);
        const finalMaxY = Math.min(canvas.height, maxY + padY);
        
        setCrop({
          unit: '%',
          x: (finalMinX / canvas.width) * 100,
          y: (finalMinY / canvas.height) * 100,
          width: ((finalMaxX - finalMinX) / canvas.width) * 100,
          height: ((finalMaxY - finalMinY) / canvas.height) * 100
        });
        
        // Create initial pixel crop so Save is immediately enabled
        setCompletedCrop({
          unit: 'px',
          x: finalMinX,
          y: finalMinY,
          width: finalMaxX - finalMinX,
          height: finalMaxY - finalMinY
        });
      }
    } catch (err) {
      console.error("Auto crop failed", err);
    }
  };

  const getCropCanvas = () => {
    if (!completedCrop || !imgRef.current) return null;
    const canvas = document.createElement('canvas');
    const scaleX = imgRef.current.naturalWidth / imgRef.current.width;
    const scaleY = imgRef.current.naturalHeight / imgRef.current.height;
    canvas.width = completedCrop.width * scaleX;
    canvas.height = completedCrop.height * scaleY;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(
      imgRef.current,
      completedCrop.x * scaleX,
      completedCrop.y * scaleY,
      completedCrop.width * scaleX,
      completedCrop.height * scaleY,
      0, 0, canvas.width, canvas.height
    );
    return canvas;
  };

  const handleScanName = async () => {
    const canvas = getCropCanvas();
    if (!canvas) return;
    
    setIsScanning(true);
    try {
      const result = await Tesseract.recognize(canvas, 'vie');
      const text = result.data.text.trim();
      
      if (isValidName(text)) {
        setScannedName(text);
      } else {
        alert(`Cảnh báo: Vùng bạn vừa quét ("${text.substring(0, 20)}...") không giống một tên người hợp lệ (chứa số, ký tự lạ, quá dài/ngắn, hoặc là chữ ký). Hệ thống đã từ chối nhận diện!`);
      }
    } catch (err) {
      console.error("OCR Error:", err);
      alert("Không thể quét chữ!");
    } finally {
      setIsScanning(false);
      setCrop(undefined);
      setCompletedCrop(null);
    }
  };

  const handleSave = async () => {
    const canvas = getCropCanvas();
    if (!canvas) return;

    processCanvasBackground(canvas);
    const base64Image = canvas.toDataURL('image/png');
    
    onSave({ base64: base64Image, scannedName });
    
    setScannedName(""); // Reset scanned name after saving
    // Auto-advance is not strictly needed here because they might want to crop multiple times, 
    // but typically they move to next. Let's keep it simple.
  };

  return (
    <div className="cropper-workspace">
      <div className="cropper-toolbar">
        <div className="toolbar-info">
          <Crop size={18} />
          <span>Kéo để chọn vùng</span>
        </div>
        
        {scannedName ? (
          <div className="metadata-hint scanned-hint">
            Tên đọc được: 
            <input 
              type="text" 
              value={scannedName} 
              onChange={e => setScannedName(e.target.value)} 
              className="scanned-input"
            />
            <button className="btn-icon" onClick={() => setScannedName("")}><X size={14}/></button>
          </div>
        ) : metadataPreview ? (
          <div className="metadata-hint">
            Đã gán tên: <strong>{metadataPreview.empCode}</strong> - {metadataPreview.empName}
          </div>
        ) : null}

        <div className="image-nav">
           <button className="btn btn-secondary" onClick={onPrevImage} disabled={currentIndex === 0}>
             <ChevronLeft size={18}/>
           </button>
           <span>Trang {currentIndex + 1} / {totalImages}</span>
           <button className="btn btn-secondary" onClick={onNextImage} disabled={currentIndex === totalImages - 1}>
             <ChevronRight size={18}/>
           </button>
        </div>

        <div className="action-buttons">
          <button 
            className="btn btn-secondary" 
            onClick={handleScanName}
            disabled={!completedCrop?.width || isScanning}
          >
            {isScanning ? <Loader2 size={18} className="spin" /> : <ScanText size={18} />}
            Quét Tên
          </button>
          
          <button 
            className="btn btn-secondary" 
            onClick={handleSave}
            title="Lưu lại và vẫn ở nguyên trang này"
            disabled={!completedCrop?.width || isScanning}
          >
            <Save size={18} />
            Lưu
          </button>

          <button 
            className="btn btn-primary" 
            onClick={() => {
              handleSave();
              if (currentIndex < totalImages - 1) {
                onNextImage();
              }
            }}
            title="Lưu lại và tự động chuyển sang chữ ký tiếp theo"
            disabled={!completedCrop?.width || isScanning}
          >
            <Save size={18} />
            Lưu & Tiếp Tục
          </button>
        </div>
      </div>
      
      <div className="cropper-container">
        <ReactCrop
          crop={crop}
          onChange={(_, percentCrop) => setCrop(percentCrop)}
          onComplete={(c) => setCompletedCrop(c)}
        >
          <img ref={imgRef} src={imageUrl} alt="Workspace" className="workspace-image" onLoad={onImageLoad} />
        </ReactCrop>
      </div>
    </div>
  );
};

export default CropperWorkspace;
