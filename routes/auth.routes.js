const express = require('express');
const authController = require('../controllers/auth.controller');
const rateLimit = require('express-rate-limit');

const router = express.Router();

// Rate limiting configurations
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many authentication attempts. Please try again later.',
    },
  },
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many registration attempts. Please try again later.',
    },
  },
});

// ==================== PUBLIC ROUTES ====================

// Signup
router.post('/signup', signupLimiter, authController.signup);

// Login
router.post('/login', authLimiter, authController.login);

// Forgot password
router.post('/forgot-password', authLimiter, authController.forgotPassword);

// Reset password
router.patch('/reset-password/:resetToken', authController.resetPassword);

// ==================== PROTECTED ROUTES ====================
router.use(authController.protect);

// Get current user
router.get('/me', (req, res) => {
  res.status(200).json({
    success: true,
    data: { user: req.user },
    message: 'User retrieved successfully',
    timestamp: new Date().toISOString(),
  });
});

// Update profile (simplified)
router.patch('/update-profile', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Profile update endpoint',
    data: { user: req.user }
  });
});

// Change password (simplified)
router.patch('/change-password', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Password change endpoint',
  });
});

// Logout
router.post('/logout', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Logged out successfully',
  });
});

// Admin dashboard
router.get('/admin/dashboard', authController.restrictTo('admin', 'super-admin'), (req, res) => {
  res.status(200).json({
    success: true,
    data: {
      message: 'Admin route accessed',
      user: req.user,
    },
    message: 'Admin dashboard data retrieved',
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;