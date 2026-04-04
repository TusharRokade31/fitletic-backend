const passport = require('passport');
const { sendUnauthorized } = require('../utils/response');

/**
 * Require a valid JWT access token.
 * Attaches `req.user` on success.
 */
const requireAuth = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      const message = info?.message || 'Authentication required';
      return sendUnauthorized(res, message);
    }
    req.user = user;
    next();
  })(req, res, next);
};

/**
 * Run passport local strategy and attach user to req.
 * Keeps error handling consistent with the rest of the API.
 */
const localAuth = (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err) return next(err);
    if (!user) return sendUnauthorized(res, info?.message || 'Invalid credentials');
    req.user = user;
    next();
  })(req, res, next);
};

module.exports = { requireAuth, localAuth };
