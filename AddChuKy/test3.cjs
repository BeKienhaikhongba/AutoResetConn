const fs = require('fs');
const JSZip = require('jszip');

async function dumpXML() {
  try {
    const data = fs.readFileSync('Copy of Danh sách thiếu chữ ký bvDucGiang.xlsx');
    const zip = await JSZip.loadAsync(data);
    for (const [path, file] of Object.entries(zip.files)) {
      if (path.match(/xl\/drawings\/drawing\d+\.xml/)) {
        const xml = await file.async("string");
        console.log(xml.substring(0, 1500));
        break;
      }
    }
  } catch(e) {
    console.error(e);
  }
}

dumpXML();
