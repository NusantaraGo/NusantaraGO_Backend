const authController = require("../controllers/authController");
const Boom = require("@hapi/boom");
const Joi = require("joi");

/**
 * Class untuk mengatur route authentikasi.
 * @class AuthUrl
 */
class AuthUrl {
  /**
   * Registers a new user and returns the user's data.
   * @typedef {import("hapi").RouteOptions} RouteOptions
   * @returns {RouteOptions} Hapi route options
   */
  registerPost() {
    return {
      method: "POST",
      path: "/auth/register",
      options: {
        auth: false,
        validate: {
          payload: registerValidateSchema(),
          failAction: (request, h, err) => {
            throw Boom.badRequest(err.message);
          },
        },
      },
      handler: authController.register,
    };
  }

  /**
   * Verifies the OTP sent to the user's email and returns the user's data
   * if the OTP is valid and the user is verified.
   * @typedef {import("hapi").RouteOptions} RouteOptions
   * @returns {RouteOptions} Hapi route options
   */
  verifyOtpPost() {
    return {
      method: "PATCH",
      path: "/auth/verify-otp",
      options: {
        auth: false,
        validate: {
          payload: verifyOtpValidateSchema(),
          failAction: (request, h, err) => {
            throw Boom.badRequest(err.message);
          },
        },
      },
      handler: authController.verifyOtp,
    };
  }

  /**
   * Handles the login endpoint.
   * @typedef {import("hapi").RouteOptions} RouteOptions
   * @returns {RouteOptions} Hapi route options
   */
  loginPost() {
    return {
      method: "POST",
      path: "/auth/login",
      options: {
        auth: false,
        validate: {
          payload: loginValidateSchema(),
          failAction: (request, h, err) => {
            throw Boom.badRequest(err.message);
          },
        },
      },
      handler: authController.login,
    };
  }

  /**
   * Retrieves user data based on the provided bearer token.
   * @typedef {import("hapi").RouteOptions} RouteOptions
   * @returns {RouteOptions} Hapi route options
   */
  getUser() {
    return {
      method: "GET",
      path: "/auth/get-user",
      handler: authController.getUser,
    };
  }

  updateUser() {
    return {
      method: "PUT",
      path: "/auth/update-user",
      options: {
        validate: {
          payload: updateUserValidateSchema(),
          failAction: (request, h, err) => {
            throw Boom.badRequest(err.message);
          },
        },
      },
      handler: authController.updateUser,
    };
  }

  logout() {
    return {
      method: "GET",
      path: "/auth/logout",
      handler: authController.deleteUser,
    };
  }
}

/**
 * Validasi untuk register endpoint.
 * Username harus alfanumerik, minimal 3 karakter, dan maksimal 30 karakter.
 * Email harus menggunakan domain @gmail.com.
 * Password harus diawali dengan kapital, minimal 6 karakter, ada angka, dan ada simbol('#!-_.').
 * Konfirmasi password harus sama dengan password.
 * @returns {Joi.ObjectSchema} - Hapi Joi schema
 */
const registerValidateSchema = () =>
  Joi.object({
    username: Joi.string()
      .trim()
      .alphanum()
      .min(3)
      .max(30)
      .required()
      .messages({
        "string.base": "Username harus berupa teks",
        "string.empty": "Username tidak boleh kosong",
        "string.alphanum": "Username hanya boleh berisi huruf dan angka",
        "string.min": "Username minimal harus terdiri dari 3 karakter",
        "string.max": "Username maksimal terdiri dari 30 karakter",
        "any.required": "Username wajib diisi",
      }),
    email: Joi.string()
      .trim()
      .pattern(/^[a-zA-Z0-9._%+-]+@gmail\.com$/)
      .email({ minDomainSegments: 2, tlds: { allow: ["com"] } })
      .required()
      .messages({
        "string.base": "Email harus berupa teks",
        "string.empty": "Email tidak boleh kosong",
        "string.pattern.base": "Email harus menggunakan domain @gmail.com",
        "string.email": "Format email tidak valid",
        "any.required": "Email wajib diisi",
      }),
    password: Joi.string()
      .trim()
      .pattern(/^(?=[A-Z])(?=.*[a-zA-Z])(?=.*\d)(?=.*[#!\-_.]).{6,}$/)
      .required()
      .messages({
        "string.base": "Password harus berupa teks",
        "string.empty": "Password tidak boleh kosong",
        "string.pattern.base":
          "Password harus diawali huruf kapital, minimal 6 karakter, mengandung angka dan simbol (#!-_.)",
        "any.required": "Password wajib diisi",
      }),

    password2: Joi.string()
      .trim()
      .valid(Joi.ref("password"))
      .required()
      .messages({
        "any.only": "Konfirmasi password tidak cocok",
        "string.empty": "Konfirmasi password tidak boleh kosong",
        "any.required": "Konfirmasi password wajib diisi",
      }),
  });

/**
 * Validasi untuk login endpoint.
 * Username harus alfanumerik, minimal 3 karakter, dan maksimal 30 karakter.
 * Password harus diawali dengan kapital, minimal 6 karakter, ada angka, dan ada simbol('#!-_.').
 * @returns {Joi.ObjectSchema} - Hapi Joi schema
 */
const loginValidateSchema = () => {
  return Joi.object({
    username: Joi.string()
      .trim()
      .alphanum()
      .min(3)
      .max(30)
      .required()
      .messages({
        "string.base": "Username harus berupa teks",
        "string.empty": "Username tidak boleh kosong",
        "string.alphanum": "Username hanya boleh berisi huruf dan angka",
        "string.min": "Username minimal harus terdiri dari 3 karakter",
        "string.max": "Username maksimal terdiri dari 30 karakter",
        "any.required": "Username wajib diisi",
      }),
    password: Joi.string()
      .trim()
      .pattern(/^(?=[A-Z])(?=.*[a-zA-Z])(?=.*\d)(?=.*[#!\-_.]).{6,}$/)
      .required()
      .messages({
        "string.base": "Password harus berupa teks",
        "string.empty": "Password tidak boleh kosong",
        "string.pattern.base":
          "Password harus diawali huruf kapital, minimal 6 karakter, mengandung angka dan simbol (#!-_.)",
        "any.required": "Password wajib diisi",
      }),
  });
};

/**
 * Validates the payload for the OTP verification endpoint.
 * Ensures that the email is a valid Gmail address and the OTP consists of digits only.

 * 
 * - Email must be in the format: localpart@gmail.com and follow the standard email format.
 * - OTP must be a string of digits.
 * 
 * Returns a Joi schema object.
 */
const verifyOtpValidateSchema = () => {
  return Joi.object({
    searchParams: Joi.string().trim().required().messages({
      "string.empty": "Parameter kosong",
      "any.required": 'Parameter "searchParams" wajib diisi',
    }),
    otp: Joi.string()
      .allow("")
      .optional()
      .pattern(/^\d{6}$|^$/)
      .messages({
        "string.pattern.base": "OTP harus berupa 6 angka atau kosong",
      }), // hanya digit (0-9)
  });
};

const updateUserValidateSchema = () => {
  return Joi.object({
    username: Joi.string().trim().required().messages({
      "string.base": "Username harus berupa teks",
      "string.empty": "Username tidak boleh kosong",
      "string.alphanum": "Username hanya boleh berisi huruf dan angka",
      "string.min": "Username minimal harus terdiri dari 3 karakter",
      "string.max": "Username maksimal terdiri dari 30 karakter",
      "any.required": "Username wajib diisi",
    }),
    email: Joi.string()
      .trim()
      .pattern(/^[a-zA-Z0-9._%+-]+@gmail\.com$/)
      .email({ minDomainSegments: 2, tlds: { allow: ["com"] } })
      .required()
      .messages({
        "string.base": "Email harus berupa teks",
        "string.empty": "Email tidak boleh kosong",
        "string.pattern.base": "Email harus menggunakan domain @gmail.com",
        "string.email": "Format email tidak valid",
        "any.required": "Email wajib diisi",
      }),
    password: Joi.string()
      .trim()
      .allow("")
      .optional()
      .pattern(/^(?=[A-Z])(?=.*[a-zA-Z])(?=.*\d)(?=.*[#!\-_.]).{6,}$/)
      .messages({
        "string.base": "Password harus berupa teks",
        "string.pattern.base":
          "Password harus diawali huruf kapital, minimal 6 karakter, mengandung angka dan simbol (#!-_.)",
      }),

    password2: Joi.string()
      .trim()
      .allow("")
      .optional()
      .valid(Joi.ref("password"))
      .messages({
        "any.only": "Konfirmasi password tidak cocok",
      }),
  });
};

// inisiasi url autentikasi
const registerPost = new AuthUrl().registerPost(); //url post register
const verifyOtpPost = new AuthUrl().verifyOtpPost(); //url post verify
const loginPost = new AuthUrl().loginPost(); //url post login
const getUser = new AuthUrl().getUser();
const updateUser = new AuthUrl().updateUser();
const logout = new AuthUrl().logout();
// end

module.exports = [
  registerPost,
  verifyOtpPost,
  loginPost,
  logout,
  getUser,
  updateUser,
];
