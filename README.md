# Auth Backend

Production-ready authentication backend with **Email/Password**, **Mobile OTP**, **Google**, **Facebook**, and **Apple Sign In**.

Built with: **Node.js · Express · MongoDB · Passport.js · Twilio · JWT**

---

## Project Structure

```
src/
├── app.js                         # Entry point
├── config/
│   ├── database.js                # MongoDB connection
│   └── passport.js                # All Passport strategies
├── controllers/
│   ├── emailAuthController.js     # Register, login, verify, reset
│   ├── otpController.js           # Send & verify mobile OTP
│   └── socialAuthController.js   # OAuth callbacks (Google/Facebook/Apple)
├── middleware/
│   ├── authMiddleware.js          # JWT protect + local auth helpers
│   ├── errorHandler.js            # Global error handler
│   ├── rateLimiter.js             # Per-route rate limits
│   └── validator.js               # Joi request validation
├── models/
│   └── User.js                    # Unified user model for all auth types
├── routes/
│   └── authRoutes.js              # All /api/auth/* routes
├── services/
│   ├── emailService.js            # Nodemailer (verification + reset emails)
│   ├── jwtService.js              # Access + refresh token management
│   └── otpService.js              # Twilio Verify / raw SMS OTP
└── utils/
    ├── logger.js                  # Winston logger
    └── response.js                # Standardised API responses
```

---

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
```bash
cp .env.example .env
# Fill in all values — see provider guides below
```

### 3. Run
```bash
npm run dev        # development (nodemon)
npm start          # production
```

---

## API Reference

All responses follow:
```json
{ "success": true, "message": "...", "data": { ... } }
{ "success": false, "message": "...", "errors": { ... } }
```

### Email / Password

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | `email, password, name?` | Create account |
| GET | `/api/auth/verify-email/:token` | — | Verify email link |
| POST | `/api/auth/resend-verification` | `email` | Resend verification email |
| POST | `/api/auth/login` | `email, password` | Login → tokens |
| POST | `/api/auth/forgot-password` | `email` | Send reset email |
| POST | `/api/auth/reset-password/:token` | `password, confirmPassword` | Set new password |

### Mobile OTP

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/otp/send` | `phone, countryCode` | Send OTP via SMS |
| POST | `/api/auth/otp/verify` | `phone, countryCode, otp` | Verify OTP → tokens |

### Social / OAuth

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/google` | Redirect to Google consent |
| GET | `/api/auth/google/callback` | Google redirect back |
| GET | `/api/auth/facebook` | Redirect to Facebook consent |
| GET | `/api/auth/facebook/callback` | Facebook redirect back |
| GET | `/api/auth/apple` | Redirect to Apple consent |
| POST | `/api/auth/apple/callback` | Apple redirect back (POST) |

### Session Management *(requires `Authorization: Bearer <accessToken>`)*

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/refresh` | `{ refreshToken }` → new token pair |
| GET | `/api/auth/me` | Current user profile |
| POST | `/api/auth/logout` | Revoke current device token |
| POST | `/api/auth/logout-all` | Revoke all device tokens |

---

## Provider Setup Guides

### 🔑 Google OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a project → **APIs & Services → Credentials → Create OAuth 2.0 Client ID**
3. Application type: **Web application**
4. Add Authorized redirect URI: `http://localhost:5000/api/auth/google/callback`
5. Copy **Client ID** and **Client Secret** into `.env`

### 🔵 Facebook OAuth
1. Go to [Facebook Developers](https://developers.facebook.com)
2. Create App → **Facebook Login → Settings**
3. Add Valid OAuth Redirect URI: `http://localhost:5000/api/auth/facebook/callback`
4. Copy **App ID** and **App Secret** into `.env`
5. Enable **Email** permission in App Review

### 🍎 Apple Sign In
1. Go to [Apple Developer Portal](https://developer.apple.com)
2. **Certificates, IDs & Profiles → Identifiers → App IDs** → enable Sign In with Apple
3. Create a **Services ID** (this is your `APPLE_CLIENT_ID`)
4. Add your domain and return URL: `https://yourdomain.com/api/auth/apple/callback`
   > ⚠️ Apple requires HTTPS and a real domain (no localhost). Use [ngrok](https://ngrok.com) for local testing.
5. Create a **Key** with Sign In with Apple enabled → download `.p8` file
6. Place the `.p8` file in `./certs/` and update `APPLE_PRIVATE_KEY_PATH`

### 📱 Twilio SMS OTP

**Option A — Twilio Verify (Recommended)**
1. Go to [Twilio Console](https://console.twilio.com)
2. **Verify → Services → Create new Service**
3. Copy the **Service SID** as `TWILIO_VERIFY_SERVICE_SID`
4. Copy Account SID and Auth Token into `.env`
5. Leave `TWILIO_PHONE_NUMBER` empty — Verify manages delivery

**Option B — Raw SMS (full control)**
1. Buy a Twilio phone number
2. Set `TWILIO_PHONE_NUMBER` to that number
3. Leave `TWILIO_VERIFY_SERVICE_SID` empty

> In development with no Twilio configured, OTPs are printed to console logs.

---

## Token Flow

```
Login / OAuth / OTP verify
         │
         ▼
┌─────────────────────┐
│  Access Token (JWT) │  ← short-lived (15 min) — sent in Authorization header
│  Refresh Token      │  ← long-lived (7 days)  — sent in POST /api/auth/refresh
└─────────────────────┘

Refresh token rotation:
  POST /api/auth/refresh { refreshToken }
  → new accessToken + new refreshToken (old one invalidated)
```

---

## Security Features

- ✅ Passwords hashed with bcrypt (12 rounds)
- ✅ JWT access tokens (15 min) + refresh token rotation
- ✅ Refresh tokens stored hashed per-device, supports logout-all
- ✅ Email verification before login (local auth)
- ✅ Password reset tokens hashed in DB, expire in 1 hour
- ✅ Rate limiting on all auth endpoints (stricter on OTP send)
- ✅ OTP attempt limiting (5 max) + 60s resend cooldown
- ✅ Joi input validation + sanitisation on all routes
- ✅ Helmet security headers
- ✅ Email enumeration prevention on forgot-password
- ✅ Passwords never returned in API responses (`select: false`)
- ✅ Social account IDs indexed for fast lookup

---

## Environment Variables

See `.env.example` for all required variables with descriptions.
