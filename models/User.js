const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    verified: { type: Boolean, default: false },
    otp: {
      type: String,
      match: /^\d{6}$/, // contoh validasi untuk OTP 6 digit
    },
    otpCreatedAt: {
      type: Date,
    },
    otpExpiredAt: {
      type: Date,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
