export const isValidName = (text) => {
  if (!text) return false;
  const t = text.trim();
  
  // Reject if too short or too long
  if (t.length < 2 || t.length > 50) return false;
  
  // Reject if it contains numbers
  if (/\d/.test(t)) return false;

  // Explicitly reject if it contains symbols that never belong in a person's name
  if (/[\/\\|_+*&^%$#@!~`":;?><,={}\[\]()]/.test(t)) return false;

  // Check for excessive special characters (OCR garbage)
  // Keep only letters and spaces to see what's left
  // Since we use Vietnamese, let's just count non-word/non-space characters
  const specialCharsMatch = t.match(/[^a-zA-Z\sàáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđĐ]/gi);
  const specialCharsCount = specialCharsMatch ? specialCharsMatch.length : 0;
  
  // If more than 2 special chars (like multiple hyphens or dots), or if high density, reject
  if (specialCharsCount > 2 || specialCharsCount > t.length * 0.2) return false;

  return true;
};

export const generateAbbreviation = (name) => {
  if (!name || typeof name !== 'string') return '';
  
  // Normalize: remove diacritics
  let cleanName = name.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/đ/g, "d").replace(/Đ/g, "D");
  
  // Remove special characters, keep letters and spaces, convert to lowercase
  cleanName = cleanName.replace(/[^a-zA-Z0-9 ]/g, "").toLowerCase().trim();
  
  if (!cleanName) return '';

  const parts = cleanName.split(/\s+/);
  
  // If it's already a single word (potentially already abbreviated), keep it
  if (parts.length <= 1) return cleanName; 
  
  // Format: LastName + Initials of other names
  // e.g. nguyen van minh -> minh + n + v -> minhnv
  const lastName = parts[parts.length - 1];
  const initials = parts.slice(0, parts.length - 1).map(p => p.charAt(0)).join('');
  
  return lastName + initials;
};
