const twilio = require('twilio');
const crypto = require('crypto');
const User = require('../models/User');
const logger = require('../utils/logger');

const OTP_EXPIRY_MINUTES = parseInt(process.env.OTP_EXPIRY_MINUTES) || 10;
const OTP_MAX_ATTEMPTS = parseInt(process.env.OTP_MAX_ATTEMPTS) || 5;
const RESEND_COOLDOWN_SECONDS = 60;

// ─── Twilio Client ────────────────────────────────────────────────────────────
let twilioClient = null;
try {
  twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
} catch {
  logger.warn('Twilio not configured. OTP will use mock mode.');
}

// ─────────────────────────────────────────────────────────────────────────────
// STRATEGY A: Twilio Verify (Recommended — handles OTP generation + delivery)
// ─────────────────────────────────────────────────────────────────────────────

const sendOTPViaTwilioVerify = async (phoneNumber) => {
  const verification = await twilioClient.verify.v2
    .services(process.env.TWILIO_VERIFY_SERVICE_SID)
    .verifications.create({ to: phoneNumber, channel: 'sms' });

  logger.info(`Twilio Verify OTP sent to ${phoneNumber} — status: ${verification.status}`);
  return { provider: 'twilio_verify', status: verification.status };
};

const verifyOTPViaTwilioVerify = async (phoneNumber, code) => {
  const result = await twilioClient.verify.v2
    .services(process.env.TWILIO_VERIFY_SERVICE_SID)
    .verificationChecks.create({ to: phoneNumber, code });

  return result.status === 'approved';
};

// ─────────────────────────────────────────────────────────────────────────────
// STRATEGY B: Self-managed OTP (stored in MongoDB, sent via Twilio SMS)
// Use this if you want full control (logging, custom expiry, attempts)
// ─────────────────────────────────────────────────────────────────────────────

const generateOTPCode = () => {
  // 6-digit cryptographically random OTP
  return String(crypto.randomInt(100000, 999999));
};

const sendOTPRaw = async (phoneNumber) => {
  const code = generateOTPCode();
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

  if (twilioClient && process.env.TWILIO_PHONE_NUMBER) {
    await twilioClient.messages.create({
      body: `Your verification code is ${code}. Valid for ${OTP_EXPIRY_MINUTES} minutes. Do not share it.`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phoneNumber
    });
  } else {
    // ⚠️  MOCK MODE — log OTP to console in development only
    if (process.env.NODE_ENV !== 'production') {
      logger.debug(`[MOCK OTP] Phone: ${phoneNumber} | Code: ${code}`);
    }
  }

  return { code, expiresAt };
};

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Send OTP to a phone number.
 * Enforces resend cooldown and saves OTP to user record.
 */
const sendOTP = async (countryCode, number) => {
  const fullPhone = `${countryCode}${number}`;

  // Find or create a pending user record
  let user = await User.findOne({ 'phone.full': fullPhone }).select('+otp');

  // Enforce resend cooldown
  if (user?.otp?.lastSentAt) {
    const secondsElapsed = (Date.now() - user.otp.lastSentAt.getTime()) / 1000;
    if (secondsElapsed < RESEND_COOLDOWN_SECONDS) {
      const waitSeconds = Math.ceil(RESEND_COOLDOWN_SECONDS - secondsElapsed);
      throw new Error(`Please wait ${waitSeconds} seconds before requesting a new OTP`);
    }
  }

  // Use Twilio Verify if configured, else raw SMS
  const useVerify = !!(twilioClient && process.env.TWILIO_VERIFY_SERVICE_SID);

  if (useVerify) {
    await sendOTPViaTwilioVerify(fullPhone);
    // No need to store OTP — Twilio manages it
    if (!user) {
      user = new User({ phone: { countryCode, number, full: fullPhone } });
    }
    user.otp = { lastSentAt: new Date(), attempts: 0 };
  } else {
    const { code, expiresAt } = await sendOTPRaw(fullPhone);
    if (!user) {
      user = new User({ phone: { countryCode, number, full: fullPhone } });
    }
    user.otp = {
      code,
      expiresAt,
      attempts: 0,
      lastSentAt: new Date()
    };
  }

  await user.save();
  return { success: true, expiresIn: `${OTP_EXPIRY_MINUTES} minutes` };
};

/**
 * Verify OTP for a given phone number.
 * Returns the user object on success.
 */
const verifyOTP = async (countryCode, number, code) => {
  const fullPhone = `${countryCode}${number}`;
  const user = await User.findOne({ 'phone.full': fullPhone }).select('+otp');

  if (!user) throw new Error('No OTP request found for this number');

  // Max attempts guard
  if (user.otp.attempts >= OTP_MAX_ATTEMPTS) {
    throw new Error('Too many failed attempts. Please request a new OTP.');
  }

  const useVerify = !!(twilioClient && process.env.TWILIO_VERIFY_SERVICE_SID);

  let isValid = false;

  if (useVerify) {
    isValid = await verifyOTPViaTwilioVerify(fullPhone, code);
  } else {
    if (!user.otp?.code) throw new Error('No OTP found. Please request a new one.');
    if (new Date() > user.otp.expiresAt) throw new Error('OTP has expired. Please request a new one.');
    isValid = user.otp.code === code;
  }

  if (!isValid) {
    user.otp.attempts += 1;
    await user.save();
    const remaining = OTP_MAX_ATTEMPTS - user.otp.attempts;
    throw new Error(`Invalid OTP. ${remaining} attempt(s) remaining.`);
  }

  // Clear OTP and mark phone verified
  user.otp = { code: undefined, expiresAt: undefined, attempts: 0, lastSentAt: undefined };
  user.isPhoneVerified = true;
  if (!user.authProviders.includes('phone')) user.authProviders.push('phone');
  user.lastLoginAt = new Date();
  user.lastLoginProvider = 'phone';
  await user.save();

  return user;
};

module.exports = { sendOTP, verifyOTP };
