const fs = require('fs');
const JSZip = require('jszip');

async function testExtract() {
  try {
    const data = fs.readFileSync('Copy of Danh sách thiếu chữ ký bvDucGiang.xlsx');
    const zip = await JSZip.loadAsync(data);
    
    // Check for drawing relations
    let relsXml = '';
    let drawingXml = '';
    
    for (const [path, file] of Object.entries(zip.files)) {
      if (path.match(/xl\/drawings\/_rels\/drawing\d+\.xml\.rels/)) {
        relsXml = await file.async("string");
      }
      if (path.match(/xl\/drawings\/drawing\d+\.xml/)) {
        drawingXml = await file.async("string");
      }
    }
    
    if (!relsXml || !drawingXml) {
      console.log("No drawings found");
      return;
    }
    
    // Parse rels
    const relMap = {};
    const relRegex = /Id="(rId\d+)"[^>]+Target="(.*?)"/g;
    let match;
    while ((match = relRegex.exec(relsXml)) !== null) {
      relMap[match[1]] = match[2].replace('../', 'xl/');
    }
    
    // Parse drawing anchors
    const anchorRegex = /<xdr:(?:twoCellAnchor|oneCellAnchor)>[\s\S]*?<xdr:from>[\s\S]*?<xdr:row>(\d+)<\/xdr:row>[\s\S]*?<a:blip[^>]*r:embed="(rId\d+)"/g;
    let anchorMatch;
    const rowToImage = {};
    let count = 0;
    while ((anchorMatch = anchorRegex.exec(drawingXml)) !== null) {
      const row = parseInt(anchorMatch[1], 10);
      const rId = anchorMatch[2];
      const imagePath = relMap[rId];
      if (imagePath) {
         rowToImage[row] = imagePath;
         count++;
      }
    }
    
    console.log("Mapped images to rows:", count);
    console.log("Sample mapping:", Object.entries(rowToImage).slice(0, 5));
    
  } catch(e) {
    console.error(e);
  }
}

testExtract();
