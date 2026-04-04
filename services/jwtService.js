const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const logger = require('../utils/logger');

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ACCESS_EXPIRES = process.env.JWT_ACCESS_EXPIRES_IN || '15m';
const REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

/**
 * Generate a short-lived access token
 */
const generateAccessToken = (userId) => {
  return jwt.sign({ sub: userId }, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
};

/**
 * Generate a long-lived refresh token and persist it in the DB
 */
const generateRefreshToken = async (userId, device = 'unknown') => {
  const token = crypto.randomBytes(64).toString('hex');

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

  await User.findByIdAndUpdate(userId, {
    $push: {
      refreshTokens: { token, device, expiresAt }
    }
  });

  return token;
};

/**
 * Verify refresh token and return a new access + refresh token pair
 */
const rotateRefreshToken = async (incomingToken, device = 'unknown') => {
  const user = await User.findOne({
    'refreshTokens.token': incomingToken,
    'refreshTokens.expiresAt': { $gt: new Date() }
  }).select('+refreshTokens');

  if (!user) throw new Error('Invalid or expired refresh token');

  // Remove old token (rotation)
  await User.findByIdAndUpdate(user._id, {
    $pull: { refreshTokens: { token: incomingToken } }
  });

  const accessToken = generateAccessToken(user._id);
  const refreshToken = await generateRefreshToken(user._id, device);

  return { accessToken, refreshToken, user };
};

/**
 * Revoke a specific refresh token (logout from one device)
 */
const revokeRefreshToken = async (userId, token) => {
  await User.findByIdAndUpdate(userId, {
    $pull: { refreshTokens: { token } }
  });
};

/**
 * Revoke ALL refresh tokens for a user (logout from all devices)
 */
const revokeAllRefreshTokens = async (userId) => {
  await User.findByIdAndUpdate(userId, { $set: { refreshTokens: [] } });
};

/**
 * Generate email verification token (stored in DB, not JWT)
 */
const generateEmailVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Generate password reset token (stored in DB, not JWT)
 */
const generatePasswordResetToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
  revokeAllRefreshTokens,
  generateEmailVerificationToken,
  generatePasswordResetToken
};
