const jwt = require("jsonwebtoken");
const User = require("../models/User");
const generateOtp = require("../utils/generateOtp");
const sendEmail = require("../utils/email");
const { Boom } = require("@hapi/boom");

exports.register = async (request, h, err) => {
  const { username, email, password, confirmPassword } = request.payload;

  // cek dataType of email,username,password,dan confirmpassword
  if (
    !(
      typeof username === "string" &&
      typeof email === "string" &&
      typeof password === "string" &&
      typeof confirmPassword === "string"
    )
  ) {
    return Boom.badRequest(
      "Terjadi kesalahan tipe data username/email/password/confirmPassword"
    );
  }

  // cek email sama sudah ada atau belum
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return h.response({ message: "Email already registered" }).code(400);
  }

  // cek username sama sudah ada atau belum
  const existingUsername = await User.findOne({ username });
  if (existingUsername) {
    return h.response({ message: "Username already registered" }).code(400);
  }

  // cek password dengan konfirmasi password
  if (password !== confirmPassword) {
    return h
      .response({ message: "Password and confirm password do not match" })
      .code(400);
  }

  const otp = generateOtp();

  const user = new User({
    email,
    password,
    otp,
    otpCreatedAt: new Date(),
  });

  await user.save();
  await sendEmail(email, otp);

  return h.response({ message: "OTP sent to email" }).code(200);
};

exports.verifyOtp = async (request, h) => {
  const { email, otp } = request.payload;

  const user = await User.findOne({ email });
  if (!user) return h.response({ message: "User not found" }).code(404);

  const isExpired = new Date() - user.otpCreatedAt > 10 * 60 * 1000; // 10 menit
  if (isExpired) return h.response({ message: "OTP expired" }).code(400);

  if (user.otp !== otp) return h.response({ message: "Invalid OTP" }).code(400);

  user.verified = true;
  user.otp = null;
  user.otpCreatedAt = null;
  await user.save();

  return h.response({ message: "Email verified successfully" });
};

exports.login = async (request, h) => {
  const { email, password } = request.payload;

  const user = await User.findOne({ email });
  if (!user || user.password !== password) {
    return h.response({ message: "Invalid email or password" }).code(401);
  }

  if (!user.verified) {
    return h.response({ message: "Email not verified" }).code(403);
  }

  const token = jwt.sign({ email }, process.env.JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: "1h",
  });

  return h.response({ token });
};
