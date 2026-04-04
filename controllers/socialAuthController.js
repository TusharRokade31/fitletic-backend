const jwtService = require('../services/jwtService');
const { sendSuccess, sendError } = require('../utils/response');
const logger = require('../utils/logger');

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

/**
 * Called after passport.authenticate('google'/'facebook'/'apple') succeeds.
 * Issues tokens and either:
 *   - redirects (browser-based OAuth flow)
 *   - returns JSON (mobile deep-link / token exchange flow)
 */
const handleSocialCallback = async (req, res, provider) => {
  try {
    const user = req.user;
    const device = req.headers['user-agent'] || 'unknown';

    // Update last login
    user.lastLoginAt = new Date();
    user.lastLoginProvider = provider;
    if (!user.authProviders.includes(provider)) user.authProviders.push(provider);
    await user.save();

    const accessToken = jwtService.generateAccessToken(user._id);
    const refreshToken = await jwtService.generateRefreshToken(user._id, device);

    // Detect if it's a mobile/SPA flow via query param
    const isMobile = req.query.mobile === 'true';

    if (isMobile) {
      // Return JSON — mobile app will handle tokens
      return sendSuccess(res, {
        accessToken,
        refreshToken,
        user: user.toPublicJSON()
      }, `${provider} login successful`);
    }

    // Redirect with tokens in URL fragment (browser SPA flow)
    // NOTE: In production prefer HttpOnly cookies or a short-lived code exchange
    const redirectUrl = new URL(`${FRONTEND_URL}/auth/callback`);
    redirectUrl.searchParams.set('accessToken', accessToken);
    redirectUrl.searchParams.set('refreshToken', refreshToken);
    redirectUrl.searchParams.set('provider', provider);

    return res.redirect(redirectUrl.toString());

  } catch (err) {
    logger.error(`Social auth callback error (${provider}):`, err);
    return res.redirect(`${FRONTEND_URL}/auth/error?message=${encodeURIComponent('Login failed')}`);
  }
};

const googleCallback = (req, res) => handleSocialCallback(req, res, 'google');
const facebookCallback = (req, res) => handleSocialCallback(req, res, 'facebook');
const appleCallback = (req, res) => handleSocialCallback(req, res, 'apple');

module.exports = { googleCallback, facebookCallback, appleCallback };
