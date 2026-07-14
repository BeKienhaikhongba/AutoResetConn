import React from 'react';
import { X, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';

const SyncLogsModal = ({ isOpen, onClose, logs, successCount, failedCount }) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content db-modal" style={{ width: '600px', maxWidth: '95vw' }}>
        <div className="modal-header">
          <h3>Kết quả đồng bộ Database</h3>
          <button className="btn-icon" onClick={onClose}><X size={20}/></button>
        </div>
        
        <div className="modal-body" style={{ maxHeight: '60vh', overflowY: 'auto' }}>
          <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
             <div style={{ color: 'var(--success)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
               <CheckCircle size={18} /> Thành công: {successCount}
             </div>
             <div style={{ color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
               <XCircle size={18} /> Thất bại/Bỏ qua: {failedCount}
             </div>
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.875rem' }}>
            {logs.map((log, idx) => {
              let color = 'var(--text-color)';
              if (log.includes('INFO:')) color = 'var(--success)';
              if (log.includes('WARNING:')) color = '#eab308'; // yellow
              if (log.includes('ERROR:')) color = 'var(--danger)';
              
              return (
                <div key={idx} style={{ color, padding: '0.25rem 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  {log}
                </div>
              );
            })}
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>
            Đóng
          </button>
        </div>
      </div>
    </div>
  );
};

export default SyncLogsModal;
