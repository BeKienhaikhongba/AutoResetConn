import React, { useState, useRef, useEffect } from 'react';
import DropZone from './components/DropZone';
import CropperWorkspace from './components/CropperWorkspace';
import PreviewPanel from './components/PreviewPanel';
import DatabaseConfig from './components/DatabaseConfig';
import SyncLogsModal from './components/SyncLogsModal';
import AboutModal from './components/AboutModal';
import QrGeneratorModal from './components/QrGeneratorModal';
import './App.css';
import { Info, QrCode } from 'lucide-react';
import { extractPdfPages } from './utils/pdfHandler';
import { parseExcelWithImages, exportTemplate } from './utils/excelHandler';
import { generateJsonExport } from './utils/exportHandler';
import { generateAbbreviation } from './utils/stringUtils';

function App() {
  const [images, setImages] = useState([]); 
  const [imageSpecificMetadata, setImageSpecificMetadata] = useState([]); 
  const [currentImageIndex, setCurrentImageIndex] = useState(0);
  
  const [metadata, setMetadata] = useState([]); 
  const [currentMetadataIndex, setCurrentMetadataIndex] = useState(0);

  const [croppedSignatures, setCroppedSignatures] = useState([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [toastMessage, setToastMessage] = useState("");

  const [isSyncing, setIsSyncing] = useState(false);
  const [syncLogs, setSyncLogs] = useState([]);
  const [showLogs, setShowLogs] = useState(false);
  const [showAbout, setShowAbout] = useState(false);
  const [showQrModal, setShowQrModal] = useState(false);
  const [syncStats, setSyncStats] = useState({ success: 0, failed: 0 });

  const handleSyncToDb = async (config) => {
    if (croppedSignatures.length === 0) {
      alert("Không có chữ ký nào để đẩy!");
      return;
    }

    setIsSyncing(true);
    try {
      const payload = croppedSignatures.map(sig => ({
        empCode: sig.empCode || sig.fileName.replace('.png', ''),
        base64_data: sig.base64.replace(/^data:image\/[a-z]+;base64,/, "")
      }));

      const response = await fetch('http://localhost:3001/api/sync-db', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config, signatures: payload })
      });

      const data = await response.json();
      setSyncLogs(data.logs || []);
      setSyncStats({ success: data.success_count || 0, failed: data.failed_count || 0 });
      setShowLogs(true);
      
      if (!data.success) {
        setToastMessage("Có lỗi xảy ra trong quá trình đồng bộ!");
      } else {
        setToastMessage(`Đồng bộ hoàn tất: ${data.success_count} thành công.`);
      }
      setTimeout(() => setToastMessage(""), 5000);
    } catch (err) {
      alert("Không thể kết nối đến Máy chủ cục bộ (Backend Server). Hãy chắc chắn bạn đã chạy lệnh npm run dev có kèm server.js!");
      console.error(err);
    } finally {
      setIsSyncing(false);
    }
  };

  const handleFileUpload = async (files) => {
    setIsProcessing(true);
    
    try {
      for (const file of files) {
        if (file.type === 'application/pdf') {
          const pdfImages = await extractPdfPages(file);
          setImages(prev => [...prev, ...pdfImages]);
          setImageSpecificMetadata(prev => [...prev, ...pdfImages.map(() => null)]);
        } else if (file.name.match(/\.(xlsx|xls)$/i)) {
          const { metadata: data, extractedImages } = await parseExcelWithImages(file);
          
          if (extractedImages && extractedImages.length > 0) {
            setToastMessage(`Đã tự động trích xuất ${extractedImages.length} ảnh chữ ký từ Excel!`);
            const newImages = extractedImages.map(img => img.base64);
            const newMetaMap = extractedImages.map(img => ({ empCode: img.empCode, empName: img.empName }));
            
            setImages(prev => [...prev, ...newImages]);
            setImageSpecificMetadata(prev => [...prev, ...newMetaMap]);
          } else {
            setMetadata(prev => [...prev, ...data]);
            setToastMessage(`Đã nạp dữ liệu ${data.length} nhân viên. Vui lòng tải file ảnh/PDF!`);
          }
          
          setTimeout(() => setToastMessage(""), 5000);
        } else if (file.type.startsWith('image/')) {
          const imageUrl = URL.createObjectURL(file);
          setImages(prev => [...prev, imageUrl]);
          setImageSpecificMetadata(prev => [...prev, null]);
        }
      }
    } catch (error) {
      console.error("Error processing file:", error);
      alert("Lỗi xử lý file!");
    } finally {
      setIsProcessing(false);
    }
  };

  const handleSaveCrop = (croppedData) => {
    let fileName = `signature_${Date.now()}.png`;
    let empCode = "";
    let empName = "";

    const specificMeta = imageSpecificMetadata[currentImageIndex];

    if (croppedData.scannedName) {
      const abbr = generateAbbreviation(croppedData.scannedName);
      empCode = abbr;
      empName = croppedData.scannedName;
      fileName = `${abbr}.png`;
    } else if (specificMeta && specificMeta.empCode) {
      empCode = specificMeta.empCode;
      empName = specificMeta.empName;
      fileName = `${empCode}.png`;
    } else if (metadata && metadata.length > currentMetadataIndex) {
      const currentMeta = metadata[currentMetadataIndex];
      empCode = currentMeta.empCode || "";
      empName = currentMeta.empName || "";
      fileName = empCode ? `${empCode}.png` : fileName;
      setCurrentMetadataIndex(prev => prev + 1);
    }

    const newSig = {
      id: Date.now(),
      base64: croppedData.base64,
      fileName: fileName,
      empCode: empCode,
      empName: empName
    };

    setCroppedSignatures(prev => [...prev, newSig]);
  };

  const handleDeleteCrop = (id) => {
    setCroppedSignatures(prev => prev.filter(sig => sig.id !== id));
  };

  const handleUpdateCrop = (id, updatedData) => {
    setCroppedSignatures(prev => prev.map(sig => sig.id === id ? { ...sig, ...updatedData } : sig));
  };

  const handleExportJson = () => {
    if (croppedSignatures.length === 0) return;
    generateJsonExport(croppedSignatures);
  };

  return (
    <div className="app-container">
      {toastMessage && (
        <div className="toast-message">
          {toastMessage}
        </div>
      )}
      
      <SyncLogsModal 
        isOpen={showLogs} 
        onClose={() => setShowLogs(false)} 
        logs={syncLogs} 
        successCount={syncStats.success} 
        failedCount={syncStats.failed} 
      />

      <header className="header">
        <h1>Signature Cropper Pro</h1>
        <div className="header-actions">
          <button className="btn btn-secondary" style={{ padding: '0.5rem', borderRadius: '50%' }} onClick={() => setShowAbout(true)} title="Thông tin phần mềm">
            <Info size={18} />
          </button>
          <DatabaseConfig onSync={handleSyncToDb} isSyncing={isSyncing} />
          
          <button className="btn btn-secondary" onClick={() => setShowQrModal(true)}>
            <QrCode size={16} style={{marginRight: '5px', verticalAlign: 'middle'}}/> Tạo Mã QR
          </button>
          <button className="btn btn-secondary" onClick={exportTemplate}>
            Tải File Excel Mẫu
          </button>
          <button className="btn btn-success" onClick={handleExportJson} disabled={croppedSignatures.length === 0}>
            Xuất File JSON nén (ZIP)
          </button>
        </div>
      </header>

      <main className="main-content">
        <div className="left-panel">
          {images.length === 0 ? (
            <DropZone onUpload={handleFileUpload} isProcessing={isProcessing} />
          ) : (
            <CropperWorkspace 
              imageUrl={images[currentImageIndex]} 
              onSave={handleSaveCrop}
              metadataPreview={imageSpecificMetadata[currentImageIndex] || (metadata.length > currentMetadataIndex ? metadata[currentMetadataIndex] : null)}
              onNextImage={() => setCurrentImageIndex(p => Math.min(p + 1, images.length - 1))}
              onPrevImage={() => setCurrentImageIndex(p => Math.max(p - 1, 0))}
              currentIndex={currentImageIndex}
              totalImages={images.length}
            />
          )}
        </div>
        
        <div className="right-panel">
          <PreviewPanel 
            signatures={croppedSignatures} 
            onDelete={handleDeleteCrop}
            onUpdate={handleUpdateCrop}
          />
        </div>
      </main>

      <AboutModal isOpen={showAbout} onClose={() => setShowAbout(false)} />
      <QrGeneratorModal isOpen={showQrModal} onClose={() => setShowQrModal(false)} />
    </div>
  );
}

export default App;
