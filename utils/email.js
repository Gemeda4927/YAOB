const nodemailer = require('nodemailer');

/**
 * Create email transporter
 */
const createTransporter = () => {
  // Check if email credentials are provided
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
    console.error('❌ Email credentials missing in .env file');
    console.error('   Please set EMAIL_USER and EMAIL_PASSWORD');
    return null;
  }

  try {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.EMAIL_PORT) || 587,
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
      // Gmail specific settings
      pool: true,
      maxConnections: 5,
      maxMessages: 100,
      rateLimit: 10, // messages per second
      // Better TLS settings
      tls: {
        ciphers: 'SSLv3',
        rejectUnauthorized: false
      },
      // Connection timeout
      connectionTimeout: 10000, // 10 seconds
      greetingTimeout: 10000,
      socketTimeout: 10000,
      // Debug logging
      debug: process.env.NODE_ENV === 'development',
      logger: process.env.NODE_ENV === 'development'
    });

    // Verify connection configuration
    transporter.verify(function(error, success) {
      if (error) {
        console.error('❌ SMTP Connection Error:', error.message);
        console.log('💡 Troubleshooting tips:');
        console.log('1. Check if Gmail app password is correct');
        console.log('2. Enable "Less secure app access" or use app password');
        console.log('3. Check if your account has 2FA enabled');
        console.log('4. Try allowing access from: https://accounts.google.com/b/0/DisplayUnlockCaptcha');
      } else {
        console.log('✅ SMTP Server is ready to send messages');
      }
    });

    return transporter;
  } catch (error) {
    console.error('❌ Failed to create email transporter:', error.message);
    return null;
  }
};

const transporter = createTransporter();

/**
 * Send email using nodemailer
 * @param {Object} options - Email options
 * @returns {Promise} - Email sending promise
 */
const sendEmail = async (options) => {
  // Check if email is disabled
  if (process.env.EMAIL_ENABLED === 'false') {
    console.log('📧 Email sending is disabled (EMAIL_ENABLED=false)');
    console.log('Email would be sent to:', options.email);
    console.log('Subject:', options.subject);
    return { messageId: 'disabled', status: 'Email sending disabled' };
  }

  // Check if transporter is available
  if (!transporter) {
    console.error('❌ Email transporter not available');
    console.log('Email would be sent to:', options.email);
    return { messageId: 'no-transporter', status: 'Transporter not available' };
  }

  try {
    // Email options
    const mailOptions = {
      from: `"${process.env.EMAIL_FROM_NAME || process.env.APP_NAME || 'Your App'}" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
      to: options.email,
      subject: options.subject,
      html: options.html || generateHtml(options),
      text: options.text || generateText(options),
      // Add headers for better email client compatibility
      headers: {
        'X-Priority': '1',
        'X-MSMail-Priority': 'High',
        'Importance': 'high'
      }
    };

    console.log(`📧 Attempting to send email to: ${options.email}`);
    console.log(`📧 Subject: ${options.subject}`);

    // Send email
    const info = await transporter.sendMail(mailOptions);
    
    console.log(`✅ Email sent successfully!`);
    console.log(`   Message ID: ${info.messageId}`);
    console.log(`   To: ${options.email}`);
    
    if (process.env.NODE_ENV === 'development') {
      console.log('📧 Preview URL (if available):', nodemailer.getTestMessageUrl(info) || 'Not available');
    }
    
    return info;
  } catch (error) {
    console.error('❌ Failed to send email:', error.message);
    console.error('Error details:', error);
    
    // Provide helpful error messages
    if (error.code === 'EAUTH') {
      console.log('\n🔐 AUTHENTICATION ERROR - Common fixes:');
      console.log('1. Generate Gmail App Password:');
      console.log('   - Go to Google Account → Security → 2-Step Verification');
      console.log('   - Click "App passwords" → Generate password for "Mail"');
      console.log('   - Use the 16-character password in EMAIL_PASSWORD');
      console.log('\n2. Enable Less Secure Apps (if no 2FA):');
      console.log('   https://myaccount.google.com/lesssecureapps');
      console.log('\n3. Allow access from this location:');
      console.log('   https://accounts.google.com/b/0/DisplayUnlockCaptcha');
    } else if (error.code === 'ECONNECTION') {
      console.log('\n🔗 CONNECTION ERROR:');
      console.log('1. Check your internet connection');
      console.log('2. Verify EMAIL_HOST and EMAIL_PORT');
      console.log('3. Try using port 465 with secure: true');
    }
    
    // Don't throw error to prevent breaking the app
    return { 
      messageId: 'error', 
      error: error.message,
      status: 'Failed to send email'
    };
  }
};

/**
 * Generate HTML email content
 */
const generateHtml = (options) => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${options.subject}</title>
      <style>
        body { 
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
          line-height: 1.6; 
          color: #333; 
          margin: 0;
          padding: 0;
          background-color: #f5f5f5;
        }
        .container { 
          max-width: 600px; 
          margin: 0 auto; 
          background-color: #ffffff;
          border-radius: 10px;
          overflow: hidden;
          box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .header { 
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white; 
          padding: 30px 20px; 
          text-align: center; 
        }
        .logo {
          font-size: 24px;
          font-weight: bold;
          margin-bottom: 10px;
        }
        .content { 
          padding: 40px 30px; 
        }
        .button { 
          display: inline-block; 
          padding: 14px 28px; 
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white; 
          text-decoration: none; 
          border-radius: 8px; 
          margin: 20px 0; 
          font-weight: bold;
          font-size: 16px;
          border: none;
          cursor: pointer;
        }
        .button:hover {
          opacity: 0.9;
          transform: translateY(-2px);
          box-shadow: 0 6px 12px rgba(102, 126, 234, 0.3);
        }
        .footer { 
          text-align: center; 
          padding: 20px; 
          color: #666; 
          font-size: 12px; 
          background-color: #f9f9f9;
          border-top: 1px solid #eee;
        }
        .code {
          background-color: #f8f9fa;
          border: 1px solid #e9ecef;
          border-radius: 4px;
          padding: 15px;
          margin: 20px 0;
          font-family: 'Courier New', monospace;
          word-break: break-all;
        }
        .warning {
          background-color: #fff3cd;
          border: 1px solid #ffc107;
          border-radius: 4px;
          padding: 15px;
          margin: 20px 0;
          color: #856404;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="logo">${process.env.APP_NAME || 'Your App'}</div>
          <h1>${options.subject}</h1>
        </div>
        <div class="content">
          ${options.html || generateContent(options)}
        </div>
        <div class="footer">
          <p>This email was sent automatically. Please do not reply.</p>
          <p>&copy; ${new Date().getFullYear()} ${process.env.APP_NAME || 'Your App'}. All rights reserved.</p>
          <p style="font-size: 10px; color: #999;">
            If you didn't request this email, you can safely ignore it.
          </p>
        </div>
      </div>
    </body>
    </html>
  `;
};

/**
 * Generate email content based on options
 */
const generateContent = (options) => {
  let content = '';
  
  if (options.context) {
    content += `<p>Hello <strong>${options.context.name || 'User'}</strong>,</p>`;
    
    if (options.context.message) {
      content += `<p>${options.context.message}</p>`;
    }
    
    if (options.context.resetToken) {
      content += `
        <div class="warning">
          <p><strong>⚠️ Development Mode:</strong> This email is being sent in development mode.</p>
          <p>In production, users would receive a secure link instead of the raw token.</p>
        </div>
        <p>Your password reset token is:</p>
        <div class="code">
          ${options.context.resetToken}
        </div>
        <p>Use this token to reset your password within the next 10 minutes.</p>
      `;
    }
    
    if (options.context.resetUrl) {
      content += `
        <p>Click the button below to reset your password:</p>
        <div style="text-align: center;">
          <a href="${options.context.resetUrl}" class="button">Reset Password</a>
        </div>
        <p>Or copy and paste this link in your browser:</p>
        <div class="code">
          ${options.context.resetUrl}
        </div>
      `;
    }
    
    if (options.context.verificationUrl) {
      content += `
        <p>Click the button below to verify your email address:</p>
        <div style="text-align: center;">
          <a href="${options.context.verificationUrl}" class="button">Verify Email</a>
        </div>
      `;
    }
    
    if (options.context.expiresIn) {
      content += `<p><strong>Note:</strong> This link expires in ${options.context.expiresIn}.</p>`;
    }
  }
  
  return content;
};

/**
 * Generate plain text email content
 */
const generateText = (options) => {
  let text = `${options.subject}\n`;
  text += '='.repeat(50) + '\n\n';
  
  if (options.context) {
    text += `Hello ${options.context.name || 'User'},\n\n`;
    
    if (options.context.message) {
      text += `${options.context.message}\n\n`;
    }
    
    if (options.context.resetToken) {
      text += `Password Reset Token: ${options.context.resetToken}\n\n`;
      text += `Use this token to reset your password within 10 minutes.\n`;
      text += `Reset URL: ${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password/${options.context.resetToken}\n\n`;
    }
    
    if (options.context.resetUrl) {
      text += `Reset Password: ${options.context.resetUrl}\n\n`;
    }
    
    if (options.context.expiresIn) {
      text += `Note: This link expires in ${options.context.expiresIn}.\n\n`;
    }
  }
  
  text += '\nBest regards,\n';
  text += `${process.env.APP_NAME || 'Your App'} Team\n`;
  text += '\n' + '='.repeat(50);
  
  return text;
};

// Email templates

/**
 * Send welcome email
 */
sendEmail.welcome = async (user) => {
  return sendEmail({
    email: user.email,
    subject: `Welcome to ${process.env.APP_NAME || 'Our Platform'}!`,
    context: {
      name: user.name,
      message: 'Thank you for registering with us! Your account has been created successfully.',
      loginUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/login`,
    },
  });
};

/**
 * Send password reset email
 */
sendEmail.passwordReset = async (user, resetToken) => {
  const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password/${resetToken}`;
  
  return sendEmail({
    email: user.email,
    subject: 'Password Reset Request',
    context: {
      name: user.name,
      message: 'You have requested to reset your password. Click the link below to set a new password.',
      resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined,
      resetUrl: resetUrl,
      expiresIn: '10 minutes',
    },
  });
};

/**
 * Send email verification email
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