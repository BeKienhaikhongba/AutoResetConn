import * as XLSX from 'xlsx';
import ExcelJS from 'exceljs';

export const parseExcelWithImages = async (file) => {
  const arrayBuffer = await file.arrayBuffer();
  const workbook = new ExcelJS.Workbook();
  await workbook.xlsx.load(arrayBuffer);

  const worksheet = workbook.worksheets[0];
  if (!worksheet) return { metadata: [], images: [] };

  let codeCol = -1;
  let nameCol = -1;
  let headerRowIndex = 1;

  worksheet.eachRow((row, rowNumber) => {
    if (codeCol !== -1) return;
    row.eachCell((cell, colNumber) => {
      const val = cell.text ? cell.text.toString().toLowerCase().trim() : '';
      if (val.includes('mã nhân viên') || val.includes('tên đăng nhập') || val.includes('tài khoản')) {
        codeCol = colNumber;
        headerRowIndex = rowNumber;
      }
      if (val.includes('tên nhân viên') || val.includes('họ và tên')) {
        nameCol = colNumber;
      }
    });
  });

  const rowMetadata = {};
  const metadataList = [];
  worksheet.eachRow((row, rowNumber) => {
    if (rowNumber <= headerRowIndex) return;

    let empCode = codeCol !== -1 && row.getCell(codeCol).text ? row.getCell(codeCol).text.toString().trim() : '';
    let empName = nameCol !== -1 && row.getCell(nameCol).text ? row.getCell(nameCol).text.toString().trim() : '';

    if (empCode || empName) {
      rowMetadata[rowNumber] = { empCode, empName };
      metadataList.push({ empCode, empName });
    }
  });

  const extractedImages = [];
  const images = worksheet.getImages();

  for (const image of images) {
    const nativeRow = image.range && image.range.tl ? image.range.tl.nativeRow : 0;
    const rowNumber = Math.floor(nativeRow) + 1;

    const imgData = workbook.model.media.find(m => m.index === image.imageId);
    if (imgData && imgData.buffer) {
      let base64 = '';
      if (imgData.buffer instanceof ArrayBuffer || imgData.buffer instanceof Uint8Array) {
        const bytes = new Uint8Array(imgData.buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        base64 = window.btoa(binary);
      } else if (typeof imgData.buffer.toString === 'function') {
        base64 = imgData.buffer.toString('base64');
      }

      const ext = imgData.extension || 'png';
      const dataUri = `data:image/${ext};base64,${base64}`;

      const meta = rowMetadata[rowNumber] || { empCode: `Unmapped_${rowNumber}`, empName: `` };

      extractedImages.push({
        base64: dataUri,
        empCode: meta.empCode,
        empName: meta.empName
      });
    }
  }

  return { metadata: metadataList, extractedImages };
};

export const parseExcelMetadata = async (file) => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onload = (e) => {
      try {
        const data = new Uint8Array(e.target.result);
        const workbook = XLSX.read(data, { type: 'array' });

        const firstSheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[firstSheetName];

        // Convert to JSON array of objects
        const json = XLSX.utils.sheet_to_json(worksheet, { header: 1 });

        if (json.length < 2) {
          resolve([]);
          return;
        }

        // Assuming row 0 is header. Look for 'Mã nhân viên' and 'Tên nhân viên'
        const headers = json[0].map(h => typeof h === 'string' ? h.toLowerCase().trim() : '');
        const codeIndex = headers.findIndex(h => h.includes('mã nhân viên'));
        const nameIndex = headers.findIndex(h => h.includes('tên nhân viên'));

        const metadata = [];
        for (let i = 1; i < json.length; i++) {
          const row = json[i];
          // Skip completely empty rows
          if (!row || row.length === 0) continue;

          const empCode = codeIndex !== -1 && row[codeIndex] ? String(row[codeIndex]).trim() : `EMP_${i}`;
          const empName = nameIndex !== -1 && row[nameIndex] ? String(row[nameIndex]).trim() : `Unknown ${i}`;

          if (empCode || empName) {
            metadata.push({ empCode, empName });
          }
        }

        resolve(metadata);
      } catch (error) {
        reject(error);
      }
    };

    reader.onerror = (error) => reject(error);
    reader.readAsArrayBuffer(file);
  });
};

export const exportTemplate = async () => {
  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet('Template');

  // Define columns
  worksheet.columns = [
    { header: 'Mã nhân viên\n(HisCode)', key: 'empCode', width: 20 },
    { header: 'Tên nhân viên\n(HisName)', key: 'empName', width: 30 },
    { header: 'Ảnh chữ ký', key: 'signature', width: 25 }
  ];

  // Cài đặt chiều cao mặc định cho TOÀN BỘ CÁC DÒNG trong sheet là 80
  // Nhờ đó người dùng cứ nhập liệu ở dòng nào là dòng đó tự động to ra bằng dòng 2
  worksheet.properties.defaultRowHeight = 80;

  // Decorate header row (Ghi đè lại dòng tiêu đề cho nhỏ gọn lại)
  const headerRow = worksheet.getRow(1);
  headerRow.height = 45; // Tăng chiều cao một chút để chứa đủ 2 dòng
  headerRow.eachCell((cell) => {
    cell.font = { name: 'Times New Roman', family: 2, size: 12, bold: true, color: { argb: 'FFFFFFFF' } };
    cell.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FF0052CC' } // Beautiful blue
    };
    cell.alignment = { vertical: 'middle', horizontal: 'center', wrapText: true };
    cell.border = {
      top: { style: 'thin' },
      left: { style: 'thin' },
      bottom: { style: 'thin' },
      right: { style: 'thin' }
    };
  });

  // Add sample data
  const rows = [];
  rows.push(worksheet.addRow(['anhhhl', 'Hà Hoàng Lam Anh', '']));
  // rows.push(worksheet.addRow(['NV002', 'Trần Thị B', '']));

  // Decorate data rows
  rows.forEach(row => {
    row.height = 80; // Set row height for images
    row.eachCell((cell) => {
      cell.alignment = { vertical: 'middle', horizontal: 'center' };
      cell.font = { name: 'Times New Roman', size: 11 };
      cell.border = {
        top: { style: 'thin' },
        left: { style: 'thin' },
        bottom: { style: 'thin' },
        right: { style: 'thin' }
      };
    });
  });

  try {
    // Trigger download
    const buffer = await workbook.xlsx.writeBuffer();
    const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'Signature_Template.xlsx';
    a.click();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    console.error("Export template error:", err);
    alert("Lỗi xuất file mẫu: " + err.message);
  }
};
