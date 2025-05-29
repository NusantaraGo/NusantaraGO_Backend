const authController = require("../controllers/authController");
const Boom = require("@hapi/boom");
const Joi = require("joi");

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
      method: "POST",
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
    username: Joi.string().trim().alphanum().min(3).max(30).required(),
    email: Joi.string()
      .trim()
      .pattern(/^[a-zA-Z0-9._%+-]+@gmail\.com$/)
      .email({ minDomainSegments: 2, tlds: { allow: ["com"] } })
      .required()
      .messages({
        "any.only": "Email harus diisi dengan akhiran @gmail.com",
        "string.pattern.base": "Email harus menggunakan domain @gmail.com",
      }),
    password: Joi.string()
      .trim()
      .pattern(
        new RegExp(/^(?=[A-Z])(?=.*[a-zA-Z])(?=.*\d)(?=.*[#!-_.]).{6,}$/)
      )
      .required()
      .messages({
        "any.only":
          "Password harus diawali dengan kapital, minimal 6 karakter, ada angka, ada simbol('#!-_.')",
      }),
    password2: Joi.string()
      .trim()
      .valid(Joi.ref("password"))
      .required()
      .messages({ "any.only": "Konfirmasi password tidak cocok" }),
  });

/**
 * Validasi untuk login endpoint.
 * Username harus alfanumerik, minimal 3 karakter, dan maksimal 30 karakter.
 * Password harus diawali dengan kapital, minimal 6 karakter, ada angka, dan ada simbol('#!-_.').
 * @returns {Joi.ObjectSchema} - Hapi Joi schema
 */
const loginValidateSchema = () => {
  return Joi.object({
    username: Joi.string().trim().alphanum().min(3).max(30).required(),
    password: Joi.string()
      .trim()
      .pattern(
        new RegExp(/^(?=[A-Z])(?=.*[a-zA-Z])(?=.*\d)(?=.*[#!-_.]).{6,}$/)
      )
      .required()
      .messages({
        "any.only":
          "Password harus diawali dengan kapital, minimal 6 karakter, ada angka, ada simbol('#!-_.')",
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
    email: Joi.string()
      .trim()
      .pattern(/^[a-zA-Z0-9._%+-]+@gmail\.com$/)
      .email({ minDomainSegments: 2, tlds: { allow: ["com"] } })
      .required()
      .messages({
        "any.only": "Email harus diisi dengan akhiran @gmail.com",
        "string.pattern.base": "Email harus menggunakan domain @gmail.com",
      }),
    otp: Joi.string()
      .trim()
      .pattern(/^\d+$/) // hanya digit (0-9)
      .required(),
  });
};

// inisiasi url autentikasi
const registerPost = new AuthUrl().registerPost(); //url post register
const verifyOtpPost = new AuthUrl().verifyOtpPost(); //url post verify
const loginPost = new AuthUrl().loginPost(); //url post login
// end

module.exports = [registerPost, verifyOtpPost, loginPost];
