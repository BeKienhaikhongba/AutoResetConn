import React, { useState, useEffect } from 'react';
import { Database, Save, X, Server, Key, User, HardDrive, CheckCircle } from 'lucide-react';
import './DatabaseConfig.css';

const DatabaseConfig = ({ onSync, isSyncing }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [config, setConfig] = useState({
    host: 'localhost',
    port: '7001',
    database: '',
    user: 'postgres',
    password: ''
  });

  useEffect(() => {
    const saved = localStorage.getItem('db_config');
    if (saved) {
      try {
        setConfig(JSON.parse(saved));
      } catch (e) { }
    }
  }, []);

  const handleChange = (e) => {
    setConfig({ ...config, [e.target.name]: e.target.value });
  };

  const handleSave = () => {
    localStorage.setItem('db_config', JSON.stringify(config));
    alert("Đã lưu cấu hình DB trên trình duyệt!");
  };

  const handleTest = async () => {
    if (!config.host || !config.database || !config.user || !config.password) {
      alert("Vui lòng điền đầy đủ cấu hình DB để kiểm tra!");
      return;
    }
    setIsTesting(true);
    try {
      const response = await fetch('http://localhost:3001/api/test-db', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config })
      });
      const data = await response.json();
      if (data.success) {
        alert("Thành công: Đã kết nối được tới Database!");
      } else {
        alert("Lỗi kết nối: " + data.error);
      }
    } catch (e) {
      alert("Lỗi: Không thể kết nối tới server Backend.");
    }
    setIsTesting(false);
  };

  const handleSync = () => {
    if (!config.host || !config.database || !config.user || !config.password) {
      alert("Vui lòng điền đầy đủ cấu hình DB!");
      return;
    }
    onSync(config);
    setIsOpen(false);
  };

  return (
    <div className="db-config-wrapper">
      <button className="btn btn-primary" onClick={() => setIsOpen(true)}>
        <Database size={18} />
        Đẩy lên Database
      </button>

      {isOpen && (
        <div className="modal-overlay">
          <div className="modal-content db-modal">
            <div className="modal-header">
              <h3>Cấu hình PostgreSQL</h3>
              <button className="btn-icon" onClick={() => setIsOpen(false)}><X size={20} /></button>
            </div>

            <div className="modal-body">
              <div className="form-group">
                <label><Server size={14} /> Host</label>
                <input type="text" name="host" value={config.host} onChange={handleChange} placeholder="localhost" />
              </div>
              <div className="form-group">
                <label><Server size={14} /> Port</label>
                <input type="text" name="port" value={config.port} onChange={handleChange} placeholder="7001" />
              </div>
              <div className="form-group">
                <label><HardDrive size={14} /> Database Name</label>
                <input type="text" name="database" value={config.database} onChange={handleChange} placeholder="db_name" />
              </div>
              <div className="form-group">
                <label><User size={14} /> Username</label>
                <input type="text" name="user" value={config.user} onChange={handleChange} placeholder="postgres" />
              </div>
              <div className="form-group">
                <label><Key size={14} /> Password</label>
                <input type="password" name="password" value={config.password} onChange={handleChange} placeholder="******" />
              </div>
            </div>

            <div className="modal-footer">
              <div className="footer-left">
                <button className="btn btn-secondary" onClick={handleTest} disabled={isTesting}>
                  <CheckCircle size={18} /> {isTesting ? "Đang test..." : "Test kết nối"}
                </button>
              </div>
              <div className="footer-right">
                <button className="btn btn-secondary" onClick={handleSave}>
                  <Save size={18} /> Lưu
                </button>
                <button className="btn btn-success" onClick={handleSync} disabled={isSyncing}>
                  {isSyncing ? "Đang đẩy..." : "Bắt Đầu Đẩy Dữ Liệu"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DatabaseConfig;