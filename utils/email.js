const nodemailer = require("nodemailer");

const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});

module.exports = async (to, otp) => {
  try {
    await transporter.sendMail({
      from: `"NusantaraGo" <${EMAIL_USER}>`,
      to,
      subject: "Your OTP Code",
      html: `
      <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333;">
        <p>Halo,</p>
        <p><strong>Kode OTP Anda adalah:</strong></p>
        <h2 style="color: #007bff;">${otp}</h2>
        <p>Silakan gunakan kode ini dalam waktu <strong>5 menit</strong>.</p>
        <p>Jika Anda tidak meminta kode ini, abaikan saja email ini.</p>
        <br/>
        <p>Terima kasih,<br/>Tim NusantaraGO</p>
      </div>
    `,
    });
  } catch (error) {
    throw new Error("❌ Gagal mengirim email ke: " + to);
  }
};
