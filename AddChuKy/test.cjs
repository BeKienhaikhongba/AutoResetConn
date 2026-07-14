const fs = require('fs');
const JSZip = require('jszip');

async function checkExcel() {
  try {
    const data = fs.readFileSync('Copy of Danh sách thiếu chữ ký bvDucGiang.xlsx');
    const zip = await JSZip.loadAsync(data);
    
    const files = Object.keys(zip.files);
    const mediaFiles = files.filter(f => f.startsWith('xl/media/'));
    
    console.log("Media files found:", mediaFiles.length);
    if (mediaFiles.length > 0) {
      console.log(mediaFiles.slice(0, 10)); // print first 10
    }
  } catch (e) {
    console.error(e);
  }
}

checkExcel();
