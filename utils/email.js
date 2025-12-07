// utils/email.js
const nodemailer = require('nodemailer');

// Create transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

/**
 * Send email using nodemailer
 * @param {Object} options - Email options
 * @param {string} options.email - Recipient email
 * @param {string} options.subject - Email subject
 * @param {string} options.template - Template name (not implemented in basic version)
 * @param {Object} options.context - Template context data
 * @returns {Promise} - Email sending promise
 */
const sendEmail = async (options) => {
  try {
    // Basic email content
    let html = `<h1>${options.subject}</h1>`;
    
    // Add context data to email body
    if (options.context) {
      html += '<ul>';
      Object.entries(options.context).forEach(([key, value]) => {
        html += `<li><strong>${key}:</strong> ${value}</li>`;
      });
      html += '</ul>';
    }
    
    // Email options
    const mailOptions = {
      from: `"${process.env.EMAIL_FROM_NAME || 'Your App'}" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
      to: options.email,
      subject: options.subject,
      text: JSON.stringify(options.context, null, 2), // Plain text version
      html: html,
    };

    // Send email
    const info = await transporter.sendMail(mailOptions);
    
    console.log(`Email sent: ${info.messageId}`);
    return info;
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
};

/**
 * Send welcome email
 * @param {Object} user - User object
 */
sendEmail.welcome = async (user) => {
  return sendEmail({
    email: user.email,
    subject: 'Welcome to Our Platform!',
    context: {
      name: user.name,
      message: 'Thank you for registering with us!',
      loginUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/login`,
    },
  });
};

/**
 * Send password reset email
 * @param {Object} user - User object
 * @param {string} resetToken - Password reset token
 */
sendEmail.passwordReset = async (user, resetToken) => {
  const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password/${resetToken}`;
  
  return sendEmail({
    email: user.email,
    subject: 'Password Reset Request',
    context: {
      name: user.name,
      message: 'You have requested to reset your password.',
      resetUrl: resetUrl,
      expiresIn: '10 minutes',
    },
  });
};

/**
 * Send email verification email
 * @param {Object} user - User object
 * @param {string} verificationToken - Email verification token
 */
sendEmail.verifyEmail = async (user, verificationToken) => {
  const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email/${verificationToken}`;
  
  return sendEmail({
    email: user.email,
    subject: 'Verify Your Email Address',
    context: {
      name: user.name,
      message: 'Please verify your email address to complete your registration.',
      verificationUrl: verificationUrl,
      expiresIn: '24 hours',
    },
  });
};

module.exports = sendEmail;