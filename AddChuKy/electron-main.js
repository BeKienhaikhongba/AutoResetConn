import { app, BrowserWindow } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
// Khởi chạy server Node.js ngầm
import './server.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let appVersion = '';
try {
  const versionData = fs.readFileSync(path.join(__dirname, 'version.json'), 'utf8');
  appVersion = JSON.parse(versionData).version;
} catch (e) {
  console.error('Không tìm thấy version.json');
}

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    title: `Signature Cropper Pro - v${appVersion}`,
    icon: path.join(__dirname, 'dist', 'vite.svg') // Hoặc đường dẫn đến file icon .ico nếu có
  });

  // Xoá menu bar mặc định của ứng dụng (File, Edit, View...)
  mainWindow.setMenu(null);

  // Load qua localhost vì server.js chạy ở port 3001 và đã serve thư mục dist
  mainWindow.loadURL('http://localhost:3001');

  // Ngăn chặn việc Electron bị đè title bởi thẻ <title> trong file index.html
  mainWindow.on('page-title-updated', (evt) => {
    evt.preventDefault();
  });

  mainWindow.on('closed', function () {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});
