const nodemailer = require('nodemailer');
const logger = require('../utils/logger');

// ─── Transporter ──────────────────────────────────────────────────────────────
let transporter = null;

const getTransporter = () => {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: parseInt(process.env.EMAIL_PORT) || 587,
      secure: process.env.EMAIL_PORT === '465',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });
  }
  return transporter;
};

// ─── Base send function ───────────────────────────────────────────────────────
const sendEmail = async ({ to, subject, html, text }) => {
  try {
    const info = await getTransporter().sendMail({
      from: process.env.EMAIL_FROM,
      to,
      subject,
      html,
      text
    });
    logger.info(`Email sent to ${to}: ${info.messageId}`);
    return info;
  } catch (err) {
    logger.error(`Email send failed to ${to}:`, err);
    throw new Error('Failed to send email. Please try again later.');
  }
};

// ─── Email Templates ──────────────────────────────────────────────────────────

const sendEmailVerification = async (email, name, token) => {
  const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

  await sendEmail({
    to: email,
    subject: 'Verify your email address',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Hello ${name || 'there'},</h2>
        <p>Please verify your email address by clicking the button below.</p>
        <p>This link expires in <strong>24 hours</strong>.</p>
        <a href="${verifyUrl}"
          style="display:inline-block; background:#1a5c3a; color:#fff; padding:12px 24px;
                 text-decoration:none; border-radius:6px; font-weight:bold; margin:16px 0;">
          Verify Email
        </a>
        <p>Or copy this URL into your browser:<br/>
          <a href="${verifyUrl}">${verifyUrl}</a>
        </p>
        <p style="color:#999; font-size:12px;">If you did not create an account, please ignore this email.</p>
      </div>
    `,
    text: `Verify your email: ${verifyUrl}`
  });
};

const sendPasswordReset = async (email, name, token) => {
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

  await sendEmail({
    to: email,
    subject: 'Reset your password',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Hello ${name || 'there'},</h2>
        <p>You requested a password reset. Click below to set a new password.</p>
        <p>This link expires in <strong>1 hour</strong>.</p>
        <a href="${resetUrl}"
          style="display:inline-block; background:#1a5c3a; color:#fff; padding:12px 24px;
                 text-decoration:none; border-radius:6px; font-weight:bold; margin:16px 0;">
          Reset Password
        </a>
        <p>Or copy this URL: <a href="${resetUrl}">${resetUrl}</a></p>
        <p style="color:#999; font-size:12px;">If you did not request this, please ignore this email. Your password won't change.</p>
      </div>
    `,
    text: `Reset your password: ${resetUrl}`
  });
};

const sendWelcomeEmail = async (email, name) => {
  await sendEmail({
    to: email,
    subject: 'Welcome! Your account is ready',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Welcome, ${name || 'there'}! 🎉</h2>
        <p>Your account has been created and verified successfully.</p>
        <a href="${process.env.FRONTEND_URL}"
          style="display:inline-block; background:#1a5c3a; color:#fff; padding:12px 24px;
                 text-decoration:none; border-radius:6px; font-weight:bold; margin:16px 0;">
          Get Started
        </a>
      </div>
    `,
    text: `Welcome! Visit ${process.env.FRONTEND_URL} to get started.`
  });
};

module.exports = {
  sendEmail,
  sendEmailVerification,
  sendPasswordReset,
  sendWelcomeEmail
};
