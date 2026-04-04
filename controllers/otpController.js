const otpService = require('../services/otpService');
const jwtService = require('../services/jwtService');
const { sendSuccess, sendError } = require('../utils/response');

// ─── Send OTP ─────────────────────────────────────────────────────────────────
const sendOTP = async (req, res) => {
  const { countryCode = '+91', phone } = req.body;

  // Strip any spaces/dashes from phone number
  const cleanPhone = phone.replace(/\D/g, '');

  const result = await otpService.sendOTP(countryCode, cleanPhone);

  return sendSuccess(
    res,
    { expiresIn: result.expiresIn },
    `OTP sent to ${countryCode}${cleanPhone}`
  );
};

// ─── Verify OTP ───────────────────────────────────────────────────────────────
const verifyOTP = async (req, res) => {
  const { countryCode = '+91', phone, otp } = req.body;

  const cleanPhone = phone.replace(/\D/g, '');
  const user = await otpService.verifyOTP(countryCode, cleanPhone, otp);

  const device = req.headers['user-agent'] || 'unknown';
  const accessToken = jwtService.generateAccessToken(user._id);
  const refreshToken = await jwtService.generateRefreshToken(user._id, device);

  return sendSuccess(
    res,
    {
      accessToken,
      refreshToken,
      user: user.toPublicJSON(),
      isNewUser: !user.name // flag so frontend can prompt profile completion
    },
    'Phone verified successfully'
  );
};

module.exports = { sendOTP, verifyOTP };
