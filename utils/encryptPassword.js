const bcrypt = require("bcrypt");

// Fungsi untuk hashing password
async function hashPasswordBcrypt(password) {
  const saltRounds = 10;
  const hash = await bcrypt.hash(password, saltRounds);
  if (!hash) {
    throw new Error("Password gagal di hash");
  }
  return hash;
}

// Fungsi untuk verifikasi password
async function verifyPassword(password, hashedPassword) {
  try {
    const isMatch = await bcrypt.compare(password, hashedPassword);
    return isMatch;
  } catch (error) {
    console.error("verifikasi password", error);
    throw error;
  }
}

// Export kedua fungsi
module.exports = {
  hashPasswordBcrypt,
  verifyPassword,
};
