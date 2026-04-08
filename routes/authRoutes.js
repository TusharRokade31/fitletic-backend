const express = require('express');
const passport = require('passport');
const router = express.Router();

const emailCtrl = require('../controllers/emailAuthController');
const otpCtrl = require('../controllers/otpController');
const socialCtrl = require('../controllers/socialAuthController');

const { requireAuth, localAuth } = require('../middleware/authMiddleware');
const validate = require('../middleware/validator');
const {
  authLimiter,
  loginLimiter,
  otpSendLimiter,
  resetLimiter
} = require('../middleware/rateLimiter');

// ─────────────────────────────────────────────────────────────────────────────
// EMAIL / PASSWORD AUTH
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/auth/register
router.post(
  '/register',
  authLimiter,
  validate('register'),
  emailCtrl.register
);

router.patch('/me', requireAuth, emailCtrl.updateMe);

// GET /api/auth/verify-email/:token
router.get('/verify-email/:token', emailCtrl.verifyEmail);

// POST /api/auth/resend-verification
router.post(
  '/resend-verification',
  authLimiter,
  validate('resendVerification'),
  emailCtrl.resendVerification
);

// POST /api/auth/login
router.post(
  '/login',
  loginLimiter,
  validate('login'),
  localAuth,          // runs passport-local, attaches req.user
  emailCtrl.login
);

// POST /api/auth/forgot-password
router.post(
  '/forgot-password',
  resetLimiter,
  validate('forgotPassword'),
  emailCtrl.forgotPassword
);

// POST /api/auth/reset-password/:token
router.post(
  '/reset-password/:token',
  resetLimiter,
  validate('resetPassword'),
  emailCtrl.resetPassword
);

// ─────────────────────────────────────────────────────────────────────────────
// MOBILE OTP AUTH
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/auth/otp/send
router.post(
  '/otp/send',
  otpSendLimiter,
  validate('sendOTP'),
  otpCtrl.sendOTP
);

// POST /api/auth/otp/verify
router.post(
  '/otp/verify',
  authLimiter,
  validate('verifyOTP'),
  otpCtrl.verifyOTP
);

// ─────────────────────────────────────────────────────────────────────────────
// GOOGLE OAUTH
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/auth/google  →  redirects to Google consent screen
router.get(
  '/google',
  passport.authenticate('google', { session: false, scope: ['profile', 'email'] })
);

// GET /api/auth/google/callback  →  Google redirects here
router.get(
  '/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: `${process.env.FRONTEND_URL}/auth/error` }),
  socialCtrl.googleCallback
);

// ─────────────────────────────────────────────────────────────────────────────
// FACEBOOK OAUTH
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/auth/facebook
router.get(
  '/facebook',
  passport.authenticate('facebook', { session: false, scope: ['email'] })
);

// GET /api/auth/facebook/callback
router.get(
  '/facebook/callback',
  passport.authenticate('facebook', { session: false, failureRedirect: `${process.env.FRONTEND_URL}/auth/error` }),
  socialCtrl.facebookCallback
);

// ─────────────────────────────────────────────────────────────────────────────
// APPLE SIGN IN
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/auth/apple
router.get(
  '/apple',
  passport.authenticate('apple', { session: false })
);

// POST /api/auth/apple/callback  — Apple uses POST for callback
router.post(
  '/apple/callback',
  passport.authenticate('apple', { session: false, failureRedirect: `${process.env.FRONTEND_URL}/auth/error` }),
  socialCtrl.appleCallback
);

// ─────────────────────────────────────────────────────────────────────────────
// SESSION MANAGEMENT  (requires valid access token)
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/auth/refresh
router.post('/refresh', validate('refreshToken'), emailCtrl.refreshToken);

// POST /api/auth/logout
router.post('/logout', requireAuth, emailCtrl.logout);

// POST /api/auth/logout-all
router.post('/logout-all', requireAuth, emailCtrl.logoutAll);

// GET /api/auth/me
router.get('/me', requireAuth, emailCtrl.me);

module.exports = router;
