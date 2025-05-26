/**
 * Converts a string into a UUID format.
 * If the input string is less than 32 characters, it will be padded using simple hashing.
 * The string is processed to generate a 32-character hexadecimal representation,
 * which is then formatted into the UUID structure (8-4-4-4-12).
 *
 * @param {string} str - The input string to be converted to a UUID.
 * @returns {string} - The formatted UUID string.
 */

async function stringToUUID(str) {
  // Pastikan string memiliki panjang minimal 32 karakter
  // Jika kurang, tambahkan padding dengan hash sederhana
  let processedStr = str;

  // Hash sederhana jika string terlalu pendek
  while (processedStr.length < 32) {
    processedStr += processedStr;
  }

  // Ambil 32 karakter pertama dan konversi ke hexadecimal
  let hex = "";
  for (let i = 0; i < 32; i++) {
    let charCode = processedStr.charCodeAt(i % processedStr.length);
    hex += charCode.toString(16).padStart(2, "0").slice(-2);
  }

  // Potong jika lebih dari 32 karakter hex
  hex = hex.slice(0, 32);

  // Format menjadi UUID (8-4-4-4-12)
  const uuid = [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");

  return uuid;
}

/**
 * Converts a UUID string back into its original string.
 * This function is the reverse of `stringToUUID()`.
 *
 * @param {string} uuid - The UUID string to be converted back into its original string.
 * @returns {string} - The original string.
 */
async function uuidToString(uuid) {
  // Hapus tanda '-' dari UUID
  const hex = uuid.replace(/-/g, "");

  // Konversi setiap 2 karakter hex menjadi karakter
  let result = "";
  for (let i = 0; i < hex.length; i += 2) {
    const hexPair = hex.slice(i, i + 2);
    const charCode = parseInt(hexPair, 16);

    // Filter karakter yang dapat dicetak
    if (charCode >= 32 && charCode <= 126) {
      result += String.fromCharCode(charCode);
    }
  }

  return result;
}

module.exports = {
  stringToUUID,
  uuidToString,
};
