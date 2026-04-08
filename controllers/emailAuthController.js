const crypto = require('crypto');
const User = require('../models/User');
const jwtService = require('../services/jwtService');
const emailService = require('../services/emailService');
const { sendSuccess, sendCreated, sendError, sendUnauthorized } = require('../utils/response');
const logger = require('../utils/logger');

// ─── Register ─────────────────────────────────────────────────────────────────
const register = async (req, res) => {
  const { email, password, employeeId } = req.body;   // ← accept employeeId
 
  const existing = await User.findOne({ email: email.toLowerCase() });
  if (existing) {
    return sendError(res, 'An account with this email already exists', 409);
  }
 
  const verificationToken  = jwtService.generateEmailVerificationToken();
  const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h
 
  const user = await User.create({
    email: email.toLowerCase(),
    password,
    ...(employeeId ? { employeeId } : {}),   // store if provided
    authProviders: ['local'],
    emailVerificationToken:   crypto.createHash('sha256').update(verificationToken).digest('hex'),
    emailVerificationExpires: verificationExpires,
  });
 
  // Issue tokens right away so the next screen (NameScreen) can call PATCH /me
  const device       = req.headers['user-agent'] || 'unknown';
  const accessToken  = jwtService.generateAccessToken(user._id);
  const refreshToken = await jwtService.generateRefreshToken(user._id, device);
 
  // Send verification email (non-blocking)
  emailService.sendEmailVerification(user.email, user.name, verificationToken)
    .catch((err) => logger.error('Failed to send verification email:', err));
 
  return sendCreated(res, {
    accessToken,
    refreshToken,
    user: user.toPublicJSON(),
  }, 'Account created. Please verify your email.');
};

const updateMe = async (req, res) => {
  const { name } = req.body;
 
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return sendError(res, 'Name is required', 400);
  }
 
  const user = await User.findByIdAndUpdate(
    req.user._id,
    { name: name.trim() },
    { new: true, runValidators: true }
  );
 
  return sendSuccess(res, { user: user.toPublicJSON() }, 'Profile updated');
};

// ─── Verify Email ─────────────────────────────────────────────────────────────
const verifyEmail = async (req, res) => {
  const { token } = req.params;

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpires: { $gt: Date.now() }
  });

  console.log(user, "user")

  if (!user) return sendError(res, 'Verification link is invalid or has expired', 400);

  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpires = undefined;
  await user.save();

  // Send welcome email
  emailService.sendWelcomeEmail(user.email, user.name).catch(() => {});

  return sendSuccess(res, {}, 'Email verified successfully. You can now log in.');
};

// ─── Resend Verification ──────────────────────────────────────────────────────
const resendVerification = async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) return sendError(res, 'No account found with this email', 404);
  if (user.isEmailVerified) return sendError(res, 'Email is already verified', 400);

  const token = jwtService.generateEmailVerificationToken();
  user.emailVerificationToken = crypto.createHash('sha256').update(token).digest('hex');
  user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await user.save();

  await emailService.sendEmailVerification(user.email, user.name, token);

  return sendSuccess(res, {}, 'Verification email sent.');
};

// ─── Login ────────────────────────────────────────────────────────────────────
const login = async (req, res) => {
  // passport-local is run before this in middleware via passport.authenticate
  const user = req.user;
  const device = req.headers['user-agent'] || 'unknown';

  const accessToken = jwtService.generateAccessToken(user._id);
  const refreshToken = await jwtService.generateRefreshToken(user._id, device);

  user.lastLoginAt = new Date();
  user.lastLoginProvider = 'local';
  await user.save();

  return sendSuccess(res, {
    accessToken,
    refreshToken,
    user: user.toPublicJSON()
  }, 'Logged in successfully');
};

// ─── Forgot Password ──────────────────────────────────────────────────────────
const forgotPassword = async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email: email.toLowerCase() });
  // Always return success to prevent email enumeration
  if (!user || !user.authProviders.includes('local')) {
    return sendSuccess(res, {}, 'If an account exists, a reset link has been sent.');
  }

  const resetToken = jwtService.generatePasswordResetToken();
  console.log("👉 THE REAL TOKEN TO PUT IN POSTMAN:", resetToken);
  user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1h
  await user.save();

  await emailService.sendPasswordReset(user.email, user.name, resetToken);

  return sendSuccess(res, {}, 'If an account exists, a reset link has been sent.');
};

// ─── Reset Password ───────────────────────────────────────────────────────────
const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  }).select('+password');

  if (!user) return sendError(res, 'Reset link is invalid or has expired', 400);

  user.password = password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  // Invalidate all refresh tokens on password reset
  user.refreshTokens = [];
  await user.save();

  return sendSuccess(res, {}, 'Password reset successful. Please log in again.');
};

// ─── Refresh Token ────────────────────────────────────────────────────────────
const refreshToken = async (req, res) => {
  const { refreshToken: token } = req.body;
  if (!token) return sendError(res, 'Refresh token required', 400);

  const device = req.headers['user-agent'] || 'unknown';
  const { accessToken, refreshToken: newRefreshToken, user } = await jwtService.rotateRefreshToken(token, device);

  return sendSuccess(res, { accessToken, refreshToken: newRefreshToken, user: user.toPublicJSON() });
};

// ─── Logout ───────────────────────────────────────────────────────────────────
const logout = async (req, res) => {
  const { refreshToken: token } = req.body;
  if (token) {
    await jwtService.revokeRefreshToken(req.user._id, token);
  }
  return sendSuccess(res, {}, 'Logged out successfully');
};

// ─── Logout All Devices ───────────────────────────────────────────────────────
const logoutAll = async (req, res) => {
  await jwtService.revokeAllRefreshTokens(req.user._id);
  return sendSuccess(res, {}, 'Logged out from all devices');
};

// ─── Get Current User ─────────────────────────────────────────────────────────
const me = async (req, res) => {
  return sendSuccess(res, { user: req.user.toPublicJSON() });
};

module.exports = {
  register,
  updateMe,
  verifyEmail,
  resendVerification,
  login,
  forgotPassword,
  resetPassword,
  refreshToken,
  logout,
  logoutAll,
  me
};
