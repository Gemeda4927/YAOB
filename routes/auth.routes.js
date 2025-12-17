const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const { protect, restrictTo, hasPermission } = require('../middleware/auth');

// Public routes
router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/forgot-password', authController.forgotPassword);
router.patch('/reset-password/:resetToken', authController.resetPassword);

// Protected routes
router.use(protect);

router.get('/me', authController.getMe);
router.patch('/update-profile', authController.updateProfile);
router.patch('/change-password', authController.changePassword);
router.post('/logout', authController.logout);

// ==================== ADMIN ROUTES ====================

// User management (Admin only)
router.get('/users', 
  restrictTo('admin', 'superadmin'), 
  hasPermission('view_users'),
  authController.getAllUsers
);

router.get('/users/:id', 
  restrictTo('admin', 'superadmin'), 
  hasPermission('view_users'),
  authController.getUserById
);

router.patch('/users/:id', 
  restrictTo('admin', 'superadmin'), 
  hasPermission('update_users'),
  authController.updateUser
);

router.delete('/users/:id', 
  restrictTo('admin', 'superadmin'), 
  hasPermission('delete_users'),
  authController.deleteUser
);

// ==================== PERMISSION MANAGEMENT ====================

// Get user's current permissions (Superadmin only)
router.get('/users/:id/permissions',
  restrictTo('superadmin'),
  hasPermission('assign_permissions'),
  authController.getUserPermissions
);

// REPLACE all permissions (current behavior) - Superadmin only
router.patch('/users/:id/permissions/assign',
  restrictTo('superadmin'),
  hasPermission('assign_permissions'),
  authController.assignPermissions
);

// ADD specific permissions (without removing existing) - Superadmin only
router.patch('/users/:id/permissions/add',
  restrictTo('superadmin'),
  hasPermission('assign_permissions'),
  authController.addPermissions
);

// REMOVE specific permissions - Superadmin only
router.patch('/users/:id/permissions/remove',
  restrictTo('superadmin'),
  hasPermission('assign_permissions'),
  authController.removePermissions
);

// Reset to default permissions based on role - Superadmin only
router.patch('/users/:id/permissions/reset',
  restrictTo('superadmin'),
  hasPermission('assign_permissions'),
  authController.resetPermissions
);

// ==================== SUPERADMIN ROUTES ====================

// Superadmin exclusive routes
router.get('/superadmin/stats', 
  restrictTo('superadmin'), 
  async (req, res) => {
    try {
      const User = require('../models/user.model');
      
      const totalUsers = await User.countDocuments({ isDeleted: false });
      const activeUsers = await User.countDocuments({ isActive: true, isDeleted: false });
      const admins = await User.countDocuments({ role: 'admin', isDeleted: false });
      const superadmins = await User.countDocuments({ role: 'superadmin', isDeleted: false });
      
      res.status(200).json({
        success: true,
        data: {
          totalUsers,
          activeUsers,
          inactiveUsers: totalUsers - activeUsers,
          admins,
          superadmins,
          regularUsers: totalUsers - admins - superadmins
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: { message: 'Failed to get stats' }
      });
    }
  }
);

module.exports = router;