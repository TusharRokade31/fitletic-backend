const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const { Strategy: LocalStrategy } = require('passport-local');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const AppleStrategy = require('passport-apple');
const bcrypt = require('bcryptjs');
const fs = require('fs');

const User = require('../models/User');
const logger = require('../utils/logger');

// ─── JWT Strategy ────────────────────────────────────────────────────────────
passport.use(
  'jwt',
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_ACCESS_SECRET
    },
    async (payload, done) => {
      try {
        const user = await User.findById(payload.sub).select('-password');
        if (!user) return done(null, false);
        if (!user.isActive) return done(null, false, { message: 'Account deactivated' });
        return done(null, user);
      } catch (err) {
        return done(err, false);
      }
    }
  )
);

// ─── Local (Email + Password) Strategy ──────────────────────────────────────
passport.use(
  'local',
  new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
        if (!user) return done(null, false, { message: 'Invalid email or password' });
        if (!user.password) return done(null, false, { message: 'Please login with your social account' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Invalid email or password' });
        if (!user.isEmailVerified) return done(null, false, { message: 'Please verify your email first' });
        if (!user.isActive) return done(null, false, { message: 'Account deactivated' });

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// ─── Google OAuth Strategy ───────────────────────────────────────────────────
passport.use(
  'google',
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      scope: ['profile', 'email']
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        if (!email) return done(null, false, { message: 'No email returned from Google' });

        // Find existing user by Google ID or email
        let user = await User.findOne({
          $or: [{ 'socialAccounts.google.id': profile.id }, { email }]
        });

        if (user) {
          // Link Google account if not already linked
          if (!user.socialAccounts?.google?.id) {
            user.socialAccounts = user.socialAccounts || {};
            user.socialAccounts.google = {
              id: profile.id,
              accessToken
            };
            user.isEmailVerified = true;
            await user.save();
          }
        } else {
          // Create new user
          user = await User.create({
            email,
            name: profile.displayName,
            profilePicture: profile.photos?.[0]?.value,
            isEmailVerified: true,
            authProviders: ['google'],
            socialAccounts: {
              google: { id: profile.id, accessToken }
            }
          });
        }

        return done(null, user);
      } catch (err) {
        logger.error('Google strategy error:', err);
        return done(err);
      }
    }
  )
);

// ─── Facebook OAuth Strategy ─────────────────────────────────────────────────
passport.use(
  'facebook',
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
      profileFields: ['id', 'emails', 'name', 'picture.type(large)']
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        const name = `${profile.name?.givenName || ''} ${profile.name?.familyName || ''}`.trim();

        let user = await User.findOne({
          $or: [
            { 'socialAccounts.facebook.id': profile.id },
            ...(email ? [{ email }] : [])
          ]
        });

        if (user) {
          if (!user.socialAccounts?.facebook?.id) {
            user.socialAccounts = user.socialAccounts || {};
            user.socialAccounts.facebook = { id: profile.id, accessToken };
            if (email && !user.isEmailVerified) user.isEmailVerified = true;
            await user.save();
          }
        } else {
          user = await User.create({
            email: email || undefined,
            name,
            profilePicture: profile.photos?.[0]?.value,
            isEmailVerified: !!email,
            authProviders: ['facebook'],
            socialAccounts: {
              facebook: { id: profile.id, accessToken }
            }
          });
        }

        return done(null, user);
      } catch (err) {
        logger.error('Facebook strategy error:', err);
        return done(err);
      }
    }
  )
);

// ─── Apple Sign In Strategy ──────────────────────────────────────────────────
// Apple only sends user info on the FIRST login — cache it in session
const applePrivateKey = process.env.APPLE_PRIVATE_KEY_PATH
  ? fs.readFileSync(process.env.APPLE_PRIVATE_KEY_PATH, 'utf8')
  : null;

if (applePrivateKey) {
  passport.use(
    'apple',
    new AppleStrategy(
      {
        clientID: process.env.APPLE_CLIENT_ID,
        teamID: process.env.APPLE_TEAM_ID,
        keyID: process.env.APPLE_KEY_ID,
        privateKeyString: applePrivateKey,
        callbackURL: process.env.APPLE_CALLBACK_URL,
        scope: ['name', 'email'],
        passReqToCallback: true
      },
      async (req, accessToken, refreshToken, idToken, profile, done) => {
        try {
          // Apple sends user details only on first auth
          const appleId = idToken.sub;
          const email = idToken.email;
          const name = req.body?.user
            ? (() => {
                const u = JSON.parse(req.body.user);
                return `${u.name?.firstName || ''} ${u.name?.lastName || ''}`.trim();
              })()
            : undefined;

          let user = await User.findOne({
            $or: [
              { 'socialAccounts.apple.id': appleId },
              ...(email ? [{ email }] : [])
            ]
          });

          if (user) {
            if (!user.socialAccounts?.apple?.id) {
              user.socialAccounts = user.socialAccounts || {};
              user.socialAccounts.apple = { id: appleId };
              await user.save();
            }
          } else {
            user = await User.create({
              email: email || undefined,
              name: name || 'Apple User',
              isEmailVerified: !!email,
              authProviders: ['apple'],
              socialAccounts: {
                apple: { id: appleId }
              }
            });
          }

          return done(null, user);
        } catch (err) {
          logger.error('Apple strategy error:', err);
          return done(err);
        }
      }
    )
  );
} else {
  logger.warn('Apple Sign In not configured: APPLE_PRIVATE_KEY_PATH missing');
}

module.exports = passport;
