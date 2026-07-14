import React, { useState } from 'react';
import { Trash2, Edit2, Check } from 'lucide-react';
import { generateAbbreviation } from '../utils/stringUtils';
import './PreviewPanel.css';

const PreviewPanel = ({ signatures, onDelete, onUpdate }) => {
  const [editingId, setEditingId] = useState(null);
  const [editName, setEditName] = useState("");

  const startEdit = (sig) => {
    setEditingId(sig.id);
    // If they edit, default to showing the full name or file name
    setEditName(sig.empName || sig.fileName.replace('.png', ''));
  };

  const saveEdit = (id) => {
    const abbr = generateAbbreviation(editName);
    const newFileName = abbr ? `${abbr}.png` : editName;
    onUpdate(id, { fileName: newFileName, empCode: abbr, empName: editName });
    setEditingId(null);
  };

  return (
    <div className="preview-panel">
      <div className="panel-header">
        <h3>Ảnh Đã Cắt ({signatures.length})</h3>
      </div>
      <div className="signatures-list">
        {signatures.length === 0 ? (
          <div className="empty-state">Chưa có ảnh nào được cắt</div>
        ) : (
          signatures.map(sig => (
            <div key={sig.id} className="signature-item">
              <div className="signature-img-wrapper">
                {/* Checkered background to show transparency */}
                <img src={sig.base64} alt={sig.fileName} className="signature-img" />
              </div>
              <div className="signature-details">
                {editingId === sig.id ? (
                  <div className="edit-mode">
                    <input 
                      type="text" 
                      value={editName} 
                      onChange={(e) => setEditName(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && saveEdit(sig.id)}
                      autoFocus
                    />
                    <button className="btn-icon text-success" onClick={() => saveEdit(sig.id)}>
                      <Check size={16} />
                    </button>
                  </div>
                ) : (
                  <div className="view-mode">
                    <span className="file-name" title={sig.fileName}>{sig.fileName}</span>
                    <button className="btn-icon" onClick={() => startEdit(sig)}>
                      <Edit2 size={14} />
                    </button>
                  </div>
                )}
                <div className="meta-info">
                  {sig.empCode && <span>{sig.empCode}</span>}
                  {sig.empName && <span>{sig.empName}</span>}
                </div>
              </div>
              <button className="btn-icon btn-delete" onClick={() => onDelete(sig.id)}>
                <Trash2 size={16} />
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default PreviewPanel;
