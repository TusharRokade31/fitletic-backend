const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    // ─── Core Identity ──────────────────────────────────────────────────────
    name: {
      type: String,
      trim: true,
      maxlength: [100, 'Name cannot exceed 100 characters']
    },

    email: {
      type: String,
      lowercase: true,
      trim: true,
      sparse: true, // allows null/undefined (Facebook users may not have email)
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email']
    },

    phone: {
      countryCode: { type: String, default: '+91' },
      number: { type: String, trim: true },
      full: { type: String, trim: true } // countryCode + number
    },

    // ─── Password (local auth) ───────────────────────────────────────────────
    password: {
      type: String,
      minlength: 8,
      select: false // never returned in queries by default
    },

    // ─── Profile ────────────────────────────────────────────────────────────
    profilePicture: { type: String },

    onboarding: {
    isComplete: { type: Boolean, default: false },
    sex: { type: String, enum: ['male', 'female'] },
    age: { type: Number },
    weight: { value: { type: Number }, unit: { type: String, enum: ['kg', 'lb'], default: 'kg' } },
    height: { value: { type: Number }, unit: { type: String, enum: ['cm', 'ft'], default: 'cm' } },
    goal: { type: String, enum: ['weight_loss', 'muscle_gain', 'healthy_foods'] },
    activityLevel: {
      type: String,
      enum: ['mostly_sitting', 'often_standing', 'regularly_walking', 'physically_intense']
    },
    targetWeight: { value: { type: Number }, unit: { type: String, enum: ['kg', 'lb'], default: 'kg' } },
    medicalConditions: [{ type: String }],
    foodPreference: { type: String, enum: ['jain', 'non_jain'] },
    referralCode: { type: String, trim: true }
  },

    // ─── Auth Providers ──────────────────────────────────────────────────────
    // Tracks which providers this user has used
    authProviders: {
      type: [String],
      enum: ['local', 'google', 'facebook', 'apple', 'phone'],
      default: []
    },

    socialAccounts: {
      google: {
        id: { type: String },
        accessToken: { type: String, select: false }
      },
      facebook: {
        id: { type: String },
        accessToken: { type: String, select: false }
      },
      apple: {
        id: { type: String }
      }
    },

    // ─── Verification ────────────────────────────────────────────────────────
    isEmailVerified: { type: Boolean, default: false },
    isPhoneVerified: { type: Boolean, default: false },

    emailVerificationToken: { type: String, select: false },
    emailVerificationExpires: { type: Date, select: false },

    // ─── OTP ────────────────────────────────────────────────────────────────
    otp: {
      code: { type: String, select: false },
      expiresAt: { type: Date, select: false },
      attempts: { type: Number, default: 0, select: false },
      lastSentAt: { type: Date, select: false }
    },

    // ─── Password Reset ──────────────────────────────────────────────────────
    passwordResetToken: { type: String, select: false },
    passwordResetExpires: { type: Date, select: false },

    // ─── Refresh Tokens (for multi-device logout) ────────────────────────────
    refreshTokens: {
      type: [
        {
          token: { type: String },
          device: { type: String },
          createdAt: { type: Date, default: Date.now },
          expiresAt: { type: Date }
        }
      ],
      select: false,
      default: []
    },

    // ─── Status ──────────────────────────────────────────────────────────────
    isActive: { type: Boolean, default: true },
    lastLoginAt: { type: Date },
    lastLoginProvider: { type: String }
  },
  {
    timestamps: true
  }
);

// ─── Indexes ─────────────────────────────────────────────────────────────────
userSchema.index({ email: 1 }, { unique: true, sparse: true });
userSchema.index({ 'phone.full': 1 }, { unique: true, sparse: true });
userSchema.index({ 'socialAccounts.google.id': 1 }, { sparse: true });
userSchema.index({ 'socialAccounts.facebook.id': 1 }, { sparse: true });
userSchema.index({ 'socialAccounts.apple.id': 1 }, { sparse: true });

// ─── Pre-save: Hash password ──────────────────────────────────────────────────
userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || !this.password) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// ─── Instance Methods ─────────────────────────────────────────────────────────
userSchema.methods.comparePassword = async function (candidatePassword) {
  if (!this.password) return false;
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.toPublicJSON = function () {
  return {
    id: this._id,
    name: this.name,
    email: this.email,
    phone: this.phone,
    onboarding: this.onboarding,
    profilePicture: this.profilePicture,
    isEmailVerified: this.isEmailVerified,
    isPhoneVerified: this.isPhoneVerified,
    authProviders: this.authProviders,
    createdAt: this.createdAt
  };
};

module.exports = mongoose.model('User', userSchema);
