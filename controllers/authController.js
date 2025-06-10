const jwt = require("jsonwebtoken");
const User = require("../models/User");
const generateOtp = require("../utils/generateOtp");
const sendEmail = require("../utils/email");
const Boom = require("@hapi/boom");
const successResponse = require("../utils/responseSuccess");
const {
  hashPasswordBcrypt,
  verifyPassword,
} = require("../utils/encryptPassword");
const { stringToUUID, uuidToString } = require("../utils/uuidGenerator");

const authController = {
  /**
   * Handles the register endpoint.
   * @param {Object} request  - The request object.
   * @param {Object} h - The response toolkit.
   * @returns {Promise} - A promise that resolves to a response object.
   */
  register: async (request, h, err) => {
    /** @type {{username: string, email: string, password: string, password2: string}} */
    const { username, email, password, password2 } = request.payload;
    const confirmPassword = password2;

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

    // cek username sama sudah ada atau belum
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      if (existingUser.verified === true) {
        return Boom.badRequest("Username sudah terdaftar");
      }
      await User.deleteOne(existingUsername);
    }

    // cek password dengan konfirmasi password
    if (password !== confirmPassword) {
      return Boom.badRequest("Password dan konfirmasi password harus sama");
    }

    // encrypt password
    let hashedPassword;
    try {
      response = await hashPasswordBcrypt(password);
      hashedPassword = response;
    } catch (err) {
      return Boom.badRequest(err);
    }

    // buat otp
    const otp = generateOtp();
    console.log("✅ Otp Berhasil di generate");

    const otpExpiredAt = new Date(Date.now() + 3 * 60 * 1000);
    console.log("✅ Otp Berhasil di generate");

    // buat user sementara dulu
    const user = new User({
      username,
      email,
      password: hashedPassword,
      otp,
      otpCreatedAt: new Date(),
      otpExpiredAt, //10 menit
      otpExpiredAt, //10 menit
    });

    // simpan user
    try {
      await user.save();
      console.log("✅ User berhasil disimpan:");
    } catch (err) {
      return Boom.badRequest("❌ Error saat menyimpan user:" + err.message);
    }

    // kirim otp ke email
    try {
      await sendEmail(email, otp);
    } catch (err) {
      return Boom.badRequest("❌ Gagal mengirim email:" + err.message);
    }

    // buat uuid email
    uuidEmail = await stringToUUID(email);
    console.log(uuidEmail);

    // kirim reponse
    return h.response(
      successResponse(
        "Verifikasi otp",
        "OTP berhasil dikirimkan ke " + email + ". Silahkan cek email anda.",
        {
          email: uuidEmail,
          otpExpiredAt: otpExpiredAt,
        }
      )
    );
  },

  /**
   * Verifies the OTP sent to the user's email.
   *
   * This function takes a request object containing a UUID search parameter and an OTP.
   * It converts the UUID back to an email address, validates the email and OTP, and
   * checks if the OTP has expired. If the OTP is valid and not expired, it updates
   * the user record to mark the email as verified and clears the OTP fields.
   *
   * @param {Object} request - The request object containing the payload with searchParams and otp.
   * @returns {Promise} - A promise that resolves to a success response or a Boom error.
   */
  verifyOtp: async (request, h) => {
    // ambil input email dan otpdari request
    const { searchParams, otp } = request.payload;

    // ubah uuid searchparams jadi string email
    const responseString = await uuidToString(searchParams);
    const email = responseString + "@gmail.com";

    console.log(email);

    // tipe data email dan otp adalah string
    if (!(typeof email === "string" && typeof otp === "string")) {
      return Boom.badRequest("Terjadi kesalahan tipe data email dan otp");
    }

    // temukan email dari database sementara
    const user = await User.findOne({ email });
    // cek masih ada atau tidak
    if (!user) return Boom.badRequest("Email belum terdaftar");

    // cek apakah otp sudah kadaluarsa atau belum
    if (!user.otpExpiredAt)
      return Boom.badRequest("Verifikasi hanya bisa dilakukan sekali");

    const isExpired = new Date() > user.otpExpiredAt;

    if (isExpired) {
      // hapus user terdaftar
      const response = await user.deleteOne({
        username: user.username,
        email: user.email,
      });
      if (response.deletedCount <= 0) {
        return Boom.badRequest("Gagal Hapus");
      }
      return Boom.badRequest("OTP sudah kadaluarsa");
    }

    if (!otp || otp === "") {
      return Boom.badRequest("OTP wajib diisi");
    }

    // cek otp database dengan otp yang diinput
    if (user.otp !== otp) return Boom.badRequest("OTP salah. Coba Lagi!");

    // ubah verified menjadi true
    user.verified = true;
    // ubah otp menjadi null
    user.otp = null;
    // ubah otpCreatedAt dan otpExpiredAt menjadi null
    user.otpCreatedAt = null;

    // save
    try {
      await user.save();
      console.log("✅ User berhasil disimpan:", user);
    } catch (err) {
      return Boom.badRequest("❌ Error saat menyimpan user:" + err.message);
    }

    // rsponse success
    return successResponse(
      "Terverifikasi!",
      `Email ${email} berhasil diverifikasi.`
    );
  },

  /**
   * Handles the login endpoint.
   * @param {Object} request - The request object.
   * @param {Object} h - The response toolkit.
   * @returns {Promise} - A promise that resolves to a response object.
   */
  login: async (request, h) => {
    // ambil payload json
    const { username, password } = request.payload;

    // tipe data email dan password adalah string
    if (!(typeof username === "string" && typeof password === "string")) {
      return Boom.badRequest("Terjadi kesalahan tipe data username/password");
    }

    // temukan username dari database
    const user = await User.findOne({ username }).select({ _id: 0 });
    // cek apakah username ada atau tidak dan password tidak sama
    if (!user) {
      return Boom.unauthorized("Kesalahan Username(tidak sesuai)");
    }

    try {
      const isMatch = await verifyPassword(password, user.password);
      if (!isMatch) {
        return Boom.unauthorized("Kesalahan Password(tidak sesuai)");
      }
    } catch (error) {
      return Boom.badRequest(error);
    }

    // sudah terverifikasi?
    if (!user.verified) {
      return Boom.forbidden("Username tidak terverifikasi. Coba lagi!");
    }

    // buat data user baru untuk ke client
    const data_user = {
      email: user.email,
    };

    // buat token jwt
    const token = jwt.sign({ data_user }, process.env.JWT_SECRET_KEY, {
      algorithm: "HS256",
      expiresIn: "1h",
    });

    if (!token) {
      return Boom.badRequest("Gagal membuat token jwt");
    }

    return h
      .response(
        successResponse(
          "Login Berhasil!",
          `User <b>${username}</b> berhasil melakukan login`
        )
      )
      .state("session", token); // <--- pastikan pakai .state()
  },

  /**
   * Handles the get user endpoint.
   * @param {Object} request - The request object.
   * @param {Object} h - The response toolkit.
   * @returns {Promise} - A promise that resolves to a response object.
   *
   * This function will return the user's data if the user is verified.
   * If the user is not verified, it will return a Boom error.
   */
  getUser: async (request, h) => {
    // cek data autentikas sekarang(username, email)
    const authNow = request.auth.credentials;
    console.log(authNow);

    // dapatkan data user
    const user = await User.findOne({ ...authNow, verified: true }).select({
      _id: 0,
      password: 0,
      otp: 0,
      otpCreatedAt: 0,
      otpExpiredAt: 0,
    });

    // mendapatkan user?
    if (!user) {
      return Boom.forbidden("User belum terverifikasi. Coba lagi!");
    }

    // kembalikan responsenya dalam bentuk json
    return h.response(
      successResponse(
        "User Terverifikasi!",
        `User <b>${user.username}</b> berhasil terverifikasi`,
        user
      )
    );
  },

  updateUser: async (request, h) => {
    try {
      // ambil credential yang diterima dari validate
      const { username, email, password, password2 } = await request.payload;

      // temukan username dari database
      const user = await User.findOne({ email, verified: true }).select({
        _id: 0,
        otp: 0,
        otpCreatedAt: 0,
        otpExpiredAt: 0,
      });

      // cek user ada dan terverikasi
      if (!user) {
        throw new Error("email tidak ditemukan/belum terverifikasi");
      }

      // ambil user sama atau tidak
      const countExistingUser = await User.countDocuments({ username });

      /* The line `set = { username };` is creating an object named `set` with a property `username`
      and assigning it the value of the `username` variable. This is a shorthand way of creating an
      object with a property that has the same name as the variable and assigning it the value of
      that variable. */
      set = {
        username,
      };

      /* This block of code is handling the scenario where a user wants to update their profile
      information, including their username and password. Here's a breakdown of what each step does: */
      if (password && password.trim().length > 0) {
        if (!(password === password2)) {
          throw new Error("konfirmasi Password tidak sama");
        }
        if (await verifyPassword(password, user.password)) {
          throw new Error("Password sama dengan sebelumnya");
        }
        set = {
          username,
          password: await hashPasswordBcrypt(password),
        };
      } else {
        if (countExistingUser > 0) {
          throw new Error("Username tidak boleh sama");
        }
      }

      /* The code `const existingUpdateUser = await User.updateOne({ email, verified: true }, { :
      set });` is updating a user's information in the database. */
      const existingUpdateUser = await User.updateOne(
        {
          email,
          verified: true,
        },
        {
          $set: set,
        }
      );
      // Check if the update was successful
      if (existingUpdateUser.modifiedCount === 1) {
        return successResponse(
          "Update Berhasil!",
          "Profile saya berhasil di update"
        );
      } else {
        throw new Error("Profile saya Gagal di update");
      }

      // lanjutkan buat username check sama atau berbeda, dan dicek sama user lain juga
      //  lembalikan response dan data terbaru agar diupdate
    } catch (err) {
      if (err) {
        return Boom.badRequest(err.message);
      } else {
        return Boom.internal("Ada kesalahan di server!");
      }
    }
  },

  deleteUser: async (request, h) => {
    const authNow = request.auth.credentials;

    console.log(!authNow);
    // Jika tidak ada sesi aktif
    if (!authNow) {
      return Boom.badRequest(
        "Gagal melakukan logout! Silahkan login terlebih dahulu."
      );
    }

    // Hapus cookie auth/token
    h.unstate("session");

    return h.response(
      successResponse(
        "Logout Berhasil!",
        `User <b>${authNow.email}</b> berhasil keluar dari sesi`
      )
    );
  },
};

module.exports = authController;
