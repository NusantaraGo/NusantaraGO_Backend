const authController = require("../controllers/authController");
const Boom = require("@hapi/boom");
const Joi = require("joi");

const registerValidateSchema = () =>
  Joi.object({
    username: Joi.string().trim().alphanum().min(3).max(30).required(),
    email: Joi.string()
      .trim()
      .email({ minDomainSegments: 2, tlds: { allow: ["com"] } })
      .required()
      .messages({ "any.only": "Email harus diisi dengan akhiran @gmail.com" }),
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

const loginValidateSchema = () => {
  Joi.object({
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

function verifyOtpValidateSchema() {
  Joi.object({
    email: Joi.string()
      .trim()
      .email({ minDomainSegments: 2, tlds: { allow: ["com"] } })
      .required()
      .messages({ "any.only": "Email harus diisi dengan akhiran @gmail.com" }),
    otp: Joi.string()
      .trim()
      .pattern(/^\d+$/) // hanya digit (0-9)
      .required(),
  });
}

module.exports = [
  {
    method: "POST",
    path: "/register",
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
  },
  {
    method: "POST",
    path: "/verify-otp",
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
  },
  {
    method: "POST",
    path: "/login",
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
  },
];
