const User = require('../models/user.model');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const validator = require('validator');
const sendEmail = require('../utils/email');

// Utility function to send response
const sendResponse = (res, statusCode, data = null, message = '', meta = null) => {
  const response = {
    success: statusCode >= 200 && statusCode < 300,
    message,
    timestamp: new Date().toISOString(),
    requestId: crypto.randomBytes(8).toString('hex'),
  };

  if (data !== null) {
    response.data = data;
  }

  if (meta !== null) {
    response.meta = meta;
  }

  res.status(statusCode).json(response);
};

// Error handling utility
const handleError = (res, error, customMessage = 'An error occurred') => {
  console.error(`[${new Date().toISOString()}] Error:`, error);

  const errorResponse = {
    success: false,
    error: {
      code: error.code || 'INTERNAL_SERVER_ERROR',
      message: customMessage,
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      traceId: crypto.randomBytes(8).toString('hex'),
    },
    timestamp: new Date().toISOString(),
    requestId: crypto.randomBytes(8).toString('hex'),
  };

  res.status(error.statusCode || 500).json(errorResponse);
};

// ==================== AUTHENTICATION CONTROLLERS ====================

/**
 * @desc    Register a new user
 * @route   POST /api/v1/auth/signup
 * @access  Public
 */
exports.signup = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Validate email
    if (!validator.isEmail(email)) {
      return sendResponse(res, 400, null, 'Please provide a valid email address');
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return sendResponse(res, 409, null, 'Email is already registered');
    }

    // Create user
    const user = await User.create({
      name,
      email,
      password,
      role: role || 'user',
    });

    // Generate token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Remove sensitive data from response
    const userResponse = user.toObject();
    delete userResponse.password;

    sendResponse(res, 201, {
      user: userResponse,
      token,
      expiresIn: 604800,
      tokenType: 'Bearer',
    }, 'Registration successful.');
  } catch (error) {
    handleError(res, error, 'Failed to create user account');
  }
};

/**
 * @desc    Login user
 * @route   POST /api/v1/auth/login
 * @access  Public
 */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return sendResponse(res, 400, null, 'Please provide email and password');
    }

    // Find user and include password
    const user = await User.findOne({ email }).select('+password');
    
    // Check if user exists
    if (!user) {
      return sendResponse(res, 401, null, 'Invalid email or password');
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / (1000 * 60));
      return sendResponse(res, 423, null, `Account is locked. Try again in ${minutesLeft} minutes`);
    }

    // Check password
    const isPasswordValid = await user.matchPassword(password);
    
    if (!isPasswordValid) {
      // Increment login attempts
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      
      // Lock account if too many attempts
      if (user.loginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000; // 15 minutes
      }
      
      await user.save({ validateBeforeSave: false });
      return sendResponse(res, 401, null, 'Invalid email or password');
    }

    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    user.lastLoginAt = Date.now();
    
    // Generate token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    await user.save();

    // Remove sensitive data
    const userResponse = user.toObject();
    delete userResponse.password;
    delete userResponse.loginAttempts;
    delete userResponse.lockUntil;

    sendResponse(res, 200, {
      user: userResponse,
      token,
      expiresIn: 7 * 24 * 60 * 60,
      tokenType: 'Bearer',
    }, 'Login successful');
  } catch (error) {
    handleError(res, error, 'Login failed');
  }
};

/**
 * @desc    Protect middleware - Verify JWT
 * @access  Private
 */
exports.protect = async (req, res, next) => {
  try {
    let token;
    
    // Get token from header
    if (req.headers.authorization?.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return sendResponse(res, 401, null, 'You are not logged in. Please log in to get access.');
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if user still exists
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return sendResponse(res, 401, null, 'The user belonging to this token no longer exists.');
    }

    // Grant access to protected route
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return sendResponse(res, 401, null, 'Invalid token. Please log in again.');
    }
    if (error.name === 'TokenExpiredError') {
      return sendResponse(res, 401, null, 'Your token has expired. Please log in again.');
    }
    handleError(res, error, 'Authentication failed');
  }
};

/**
 * @desc    Restrict to certain roles
 * @param   {...String} roles - Allowed roles
 * @access  Private
 */
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return sendResponse(res, 401, null, 'Authentication required');
    }

    if (!roles.includes(req.user.role)) {
      return sendResponse(res, 403, null, 'You do not have permission to perform this action');
    }

    next();
  };
};

/**
 * @desc    Get current user profile
 * @route   GET /api/v1/auth/me
 * @access  Private
 */
exports.getMe = async (req, res) => {
  try {
    const user = req.user;
    
    sendResponse(res, 200, { user }, 'Profile retrieved successfully');
  } catch (error) {
    handleError(res, error, 'Failed to get profile');
  }
};

/**
 * @desc    Forgot password
 * @route   POST /api/v1/auth/forgot-password
 * @access  Public
 */
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return sendResponse(res, 400, null, 'Email is required');
    }

    const user = await User.findOne({ email });
    
    if (!user) {
      return sendResponse(res, 200, null, 'If your email is registered, you will receive a password reset link');
    }

    // Generate reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    sendResponse(res, 200, {
      resetToken,
      expiresIn: 600,
    }, 'Password reset email sent');
  } catch (error) {
    handleError(res, error, 'Failed to process password reset request');
  }
};

/**
 * @desc    Reset password
 * @route   PATCH /api/v1/auth/reset-password/:resetToken
 * @access  Public
 */
exports.resetPassword = async (req, res) => {
  try {
    const { resetToken } = req.params;
    const { password } = req.body;

    if (!password) {
      return sendResponse(res, 400, null, 'Password is required');
    }

    // Hash token to compare with stored token
    const hashedToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return sendResponse(res, 400, null, 'Token is invalid or has expired');
    }

    // Update password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    
    // Generate new token for immediate login
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    await user.save();

    // Remove sensitive data
    const userResponse = user.toObject();
    delete userResponse.password;

    sendResponse(res, 200, {
      user: userResponse,
      token,
    }, 'Password has been reset successfully');
  } catch (error) {
    handleError(res, error, 'Failed to reset password');
  }
};

module.exports = exports;