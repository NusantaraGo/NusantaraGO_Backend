// import library
require("dotenv").config();
const Hapi = require("@hapi/hapi");
const mongoose = require("mongoose");
const authRoutes = require("./routes/auth");
const boom = require("@hapi/boom");
const jwt = require("jsonwebtoken");

const MONGODB_URI = process.env.MONGODB_URI;
const PORT = process.env.PORT || 3000;
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;
const NODE_ENV = process.env.NODE_ENV;
const PASSWORD_COOKIE = process.env.PASSWORD_COOKIE;

/**
 * Inits the server, connects to MongoDB, and registers the auth route.
 * @param {string} MONGODB_URI - The URI to MongoDB.
 * @param {number} PORT - The port number to listen on.
 * @param {string} JWT_SECRET_KEY - The secret key for JWT.
 */

const init = async (MONGODB_URI, PORT, JWT_SECRET_KEY) => {
  if (
    !(
      typeof MONGODB_URI == "string" &&
      typeof PORT == "number" &&
      typeof JWT_SECRET_KEY == "string"
    )
  ) {
    boom.badRequest(
      "invalid type of data in MONGODB URL, PORT, JWT SECRET_KEY"
    );
  }

  // mendapatkan connect atau tidak
  const result = await mongoose.connect(MONGODB_URI, {
    dbName: "NusantaraGo",
  });

  if (!result) {
    return boom.badRequest("MongoDB Gagal Terkoneksi");
  }

  console.log("Connected to MongoDB");

  const server = Hapi.server({
    port: PORT || 3000,
    host: "localhost",
    routes: {
      cors: {
        origin: ["*"], // atau spesifik ['http://localhost:5173']
        credentials: true, // agar cookie bisa dikirim
      },
    },
  });

  await server.register([require("hapi-auth-jwt2"), require("@hapi/cookie")]);

  const validate = async (decoded, request, h) => {
    console.log(decoded, request, h);
    return { isValid: true }; // Bisa tambahkan pengecekan ke DB jika perlu
  };

  // buat untuk jwt konfigurasi
  server.auth.strategy("jwt", "jwt", {
    key: JWT_SECRET_KEY,
    validate,
    verifyOptions: { algorithms: ["HS256"] },
  });

  // Set konfigurasi cookie
  server.auth.strategy("session", "cookie", {
    cookie: {
      name: "session",
      password: PASSWORD_COOKIE,
      path: "/",
      ttl: 24 * 60 * 60 * 1000, // 1 hari
      isSecure: NODE_ENV === "production", // HTTPS di production
      isHttpOnly: NODE_ENV === "production", // Anti-XSS
      isSameSite: "Lax", // atau "None" jika butuh cross-site (dengan HTTPS)
      // encoding: "none", // ⬅️ penting untuk JWT! Jangan biarkan Hapi auto-encode
    },
    validate: async (request, session) => {
      try {
        const decoded = jwt.verify(session, JWT_SECRET_KEY);
        if (!decoded) {
          throw new Error("JWT Expired");
        }
        return {
          isValid: true,
          credentials: decoded.data_user, // simpan info user ke credentials
        };
      } catch (err) {
        if (err) {
          return boom.badRequest(err.message);
        } else {
          return boom.badRequest("Session expired/tidak ditemukan");
        }
      }
    },
  });

  server.auth.default("session");

  server.route(authRoutes);

  await server.start();
  console.log("Server berjalan di %s", server.info.uri);
};

try {
  init(MONGODB_URI, PORT, JWT_SECRET_KEY);
} catch (err) {
  console.log(err);
}
