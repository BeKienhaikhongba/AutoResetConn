import JSZip from 'jszip';

export const generateJsonExport = async (signatures) => {
  const zip = new JSZip();
  const folderName = `signatures_export_${Date.now()}`;
  const rootFolder = zip.folder(folderName);
  const imgFolder = rootFolder.folder("images");

  // Format based on requested JSON structure
  const formattedSignatures = signatures.map(sig => {
    // Strip the data:image/png;base64, part for pure base64
    const pureBase64 = sig.base64.replace(/^data:image\/[a-z]+;base64,/, "");
    
    // Add image to ZIP
    imgFolder.file(sig.fileName, pureBase64, { base64: true });
    
    return {
      full_name: sig.empCode || sig.fileName.replace('.png', ''),
      original_relative_path: sig.fileName,
      output_file_name: sig.fileName,
      output_relative_path: `images/${sig.fileName}`,
      base64_data: pureBase64
    };
  });

  const exportData = {
    departments: [
      {
        department_name: "Input Root",
        signatures: formattedSignatures
      }
    ]
  };

  // Add JSON to ZIP
  rootFolder.file("data.json", JSON.stringify(exportData, null, 2));

  // Generate ZIP file
  const zipBlob = await zip.generateAsync({ type: "blob" });
  
  // Download ZIP
  const url = URL.createObjectURL(zipBlob);
  const downloadAnchorNode = document.createElement('a');
  downloadAnchorNode.setAttribute("href", url);
  downloadAnchorNode.setAttribute("download", `${folderName}.zip`);
  document.body.appendChild(downloadAnchorNode);
  downloadAnchorNode.click();
  downloadAnchorNode.remove();
  URL.revokeObjectURL(url);
};
