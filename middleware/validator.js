const Joi = require('joi');
const { sendValidationError } = require('../utils/response');

// ─── Schema Library ───────────────────────────────────────────────────────────
const schemas = {
  register: Joi.object({
    email: Joi.string().email().lowercase().required(),
    password: Joi.string()
      .min(8)
      .max(72)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .required()
      .messages({
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, and one number'
      }),
    name: Joi.string().min(2).max(100).optional(),
  }),

  login: Joi.object({
    email: Joi.string().email().lowercase().required(),
    password: Joi.string().required()
  }),

  forgotPassword: Joi.object({
    email: Joi.string().email().lowercase().required()
  }),

  resetPassword: Joi.object({
    password: Joi.string()
      .min(8)
      .max(72)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .required()
      .messages({
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, and one number'
      }),
    confirmPassword: Joi.any().valid(Joi.ref('password')).required().messages({
      'any.only': 'Passwords do not match'
    })
  }),

  sendOTP: Joi.object({
    phone: Joi.string()
      .pattern(/^\d{7,15}$/)
      .required()
      .messages({ 'string.pattern.base': 'Please provide a valid phone number (digits only)' }),
    countryCode: Joi.string()
      .pattern(/^\+\d{1,4}$/)
      .default('+91')
  }),

  verifyOTP: Joi.object({
    phone: Joi.string().pattern(/^\d{7,15}$/).required(),
    countryCode: Joi.string().pattern(/^\+\d{1,4}$/).default('+91'),
    otp: Joi.string().length(6).pattern(/^\d{6}$/).required().messages({
      'string.length': 'OTP must be 6 digits',
      'string.pattern.base': 'OTP must contain only digits'
    })
  }),

  refreshToken: Joi.object({
    refreshToken: Joi.string().required()
  }),

  resendVerification: Joi.object({
    email: Joi.string().email().lowercase().required()
  })
};

// ─── Middleware factory ───────────────────────────────────────────────────────
const validate = (schemaName) => (req, res, next) => {
  const schema = schemas[schemaName];
  if (!schema) return next();

  const { error, value } = schema.validate(req.body, {
    abortEarly: false,
    stripUnknown: true
  });

  if (error) {
    const errors = error.details.reduce((acc, detail) => {
      const key = detail.path.join('.');
      acc[key] = detail.message.replace(/['"]/g, '');
      return acc;
    }, {});
    return sendValidationError(res, errors);
  }

  req.body = value; // use the sanitised/coerced value
  next();
};

module.exports = validate;
