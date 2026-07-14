export const processCanvasBackground = (canvas) => {
  const ctx = canvas.getContext('2d');
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const data = imageData.data;
  
  // Signature cropping assumption: White/light background, dark ink.
  // We'll turn pixels with high brightness transparent.
  // And maybe enhance the dark pixels to solid black or original color.
  
  // Thresholds (0-255)
  const brightnessThreshold = 200; 
  
  for (let i = 0; i < data.length; i += 4) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];
    // a = data[i + 3]
    
    // Calculate brightness (simple average or perceived luminance)
    const brightness = (r * 299 + g * 587 + b * 114) / 1000;
    
    if (brightness > brightnessThreshold) {
      // Turn transparent
      data[i + 3] = 0; 
    } else {
      // Optional: Enhance dark ink by making it slightly darker/more opaque
      // data[i+3] = 255;
    }
  }
  
  ctx.putImageData(imageData, 0, 0);
};
