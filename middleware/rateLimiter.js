const rateLimit = require('express-rate-limit');
const { sendError } = require('../utils/response');

const rateLimitHandler = (req, res) => {
  sendError(res, 'Too many requests. Please try again later.', 429);
};

// General auth rate limit
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  handler: rateLimitHandler,
  standardHeaders: true,
  legacyHeaders: false
});

// Login — tighter limit to slow brute force
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  handler: rateLimitHandler,
  standardHeaders: true,
  legacyHeaders: false
});

// OTP send — very tight limit (each SMS costs money)
const otpSendLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  keyGenerator: (req) => req.body.phone || req.ip,
  handler: rateLimitHandler,
  standardHeaders: true,
  legacyHeaders: false
});

// Password reset
const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  handler: rateLimitHandler,
  standardHeaders: true,
  legacyHeaders: false
});

module.exports = { authLimiter, loginLimiter, otpSendLimiter, resetLimiter };
