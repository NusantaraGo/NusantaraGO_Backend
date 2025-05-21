function validatePassword(password) {
  // Minimal 6 karakter, ada angka, ada simbol #
  const passwordRegex = /^(?=[A-Z])(?=.*[a-zA-Z])(?=.*\d)(?=.*[#!-_.]).{6,}$/;
  return passwordRegex.test(password);
}

module.exports = validatePassword;
