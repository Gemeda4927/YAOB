const User = require('../models/user.model');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const validator = require('validator');

// Response utility
const sendResponse = (res, statusCode, data = null, message = '') => {
  const response = {
    success: statusCode >= 200 && statusCode < 300,
    message: message || (statusCode >= 200 && statusCode < 300 ? 'Success' : 'Error'),
    timestamp: new Date().toISOString(),
  };

  if (data !== null) {
    response.data = data;
  }

  return res.status(statusCode).json(response);
};

// Error handler
const handleError = (res, error, customMessage = 'An error occurred') => {
  console.error('Controller Error:', error);
  
  const errorResponse = {
    success: false,
    error: {
      message: customMessage,
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
    },
    timestamp: new Date().toISOString(),
  };

  return res.status(error.statusCode || 500).json(errorResponse);
};

// ==================== BASIC AUTH CONTROLLERS ====================

exports.signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return sendResponse(res, 400, null, 'Name, email, and password are required');
    }

    if (!validator.isEmail(email)) {
      return sendResponse(res, 400, null, 'Invalid email address');
    }

    if (password.length < 8) {
      return sendResponse(res, 400, null, 'Password must be at least 8 characters');
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return sendResponse(res, 409, null, 'Email already registered');
    }

    // Create user with default 'user' role
    const user = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password,
      role: 'user',
      permissions: ['view_profile', 'update_profile', 'change_password'],
    });

    const token = jwt.sign(
      { 
        id: user._id,
        role: user.role,
        permissions: user.permissions
      },
      process.env.JWT_SECRET || 'development-secret-key',
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    const userResponse = user.toObject();
    delete userResponse.password;

    return sendResponse(res, 201, {
      user: userResponse,
      token,
      expiresIn: 604800,
      tokenType: 'Bearer',
    }, 'Registration successful');
  } catch (error) {
    handleError(res, error, 'Failed to create account');
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return sendResponse(res, 400, null, 'Email and password required');
    }

    if (!validator.isEmail(email)) {
      return sendResponse(res, 400, null, 'Invalid email address');
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password');
    
    if (!user) {
      return sendResponse(res, 401, null, 'Invalid email or password');
    }

    const isPasswordValid = await user.matchPassword(password);
    
    if (!isPasswordValid) {
      return sendResponse(res, 401, null, 'Invalid email or password');
    }

    const token = jwt.sign(
      { 
        id: user._id,
        role: user.role,
        permissions: user.permissions
      },
      process.env.JWT_SECRET || 'development-secret-key',
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    const userResponse = user.toObject();
    delete userResponse.password;

    return sendResponse(res, 200, {
      user: userResponse,
      token,
      expiresIn: 7 * 24 * 60 * 60,
      tokenType: 'Bearer',
    }, 'Login successful');
  } catch (error) {
    handleError(res, error, 'Login failed');
  }
};

exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    if (!user) {
      return sendResponse(res, 404, null, 'User not found');
    }

    const userResponse = user.toObject();
    delete userResponse.password;

    return sendResponse(res, 200, { user: userResponse }, 'Profile retrieved');
  } catch (error) {
    handleError(res, error, 'Failed to get profile');
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return sendResponse(res, 400, null, 'Email is required');
    }

    if (!validator.isEmail(email)) {
      return sendResponse(res, 400, null, 'Invalid email address');
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    
    if (!user) {
      // For security, don't reveal if email exists
      return sendResponse(res, 200, null, 'If your email is registered, you will receive a reset link');
    }

    if (!user.isActive || user.isDeleted) {
      return sendResponse(res, 400, null, 'Account is deactivated');
    }

    // Generate reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // In development, show the token
    if (process.env.NODE_ENV === 'development') {
      return sendResponse(res, 200, {
        message: 'Password reset token generated',
        resetToken,
        expiresIn: 600, // 10 minutes
      }, 'Reset token generated');
    }

    return sendResponse(res, 200, {
      message: 'If your email is registered, you will receive a reset link',
    }, 'Reset email sent');
  } catch (error) {
    handleError(res, error, 'Failed to process password reset');
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { resetToken } = req.params;
    const { password } = req.body;

    if (!password) {
      return sendResponse(res, 400, null, 'Password is required');
    }

    if (password.length < 8) {
      return sendResponse(res, 400, null, 'Password must be at least 8 characters');
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

    // Check if account is active
    if (!user.isActive || user.isDeleted) {
      return sendResponse(res, 400, null, 'Account is deactivated');
    }

    // Update password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    
    const token = jwt.sign(
      { 
        id: user._id,
        role: user.role,
        permissions: user.permissions
      },
      process.env.JWT_SECRET || 'development-secret-key',
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
    
    await user.save();

    const userResponse = user.toObject();
    delete userResponse.password;

    return sendResponse(res, 200, {
      user: userResponse,
      token,
      expiresIn: 7 * 24 * 60 * 60,
      tokenType: 'Bearer',
    }, 'Password has been reset successfully');
  } catch (error) {
    handleError(res, error, 'Failed to reset password');
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const { name } = req.body;
    
    if (!name || name.trim().length < 2) {
      return sendResponse(res, 400, null, 'Name must be at least 2 characters');
    }
    
    // Update user
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { name: name.trim() },
      { new: true, runValidators: true }
    );

    const userResponse = user.toObject();
    delete userResponse.password;

    return sendResponse(res, 200, { user: userResponse }, 'Profile updated successfully');
  } catch (error) {
    handleError(res, error, 'Failed to update profile');
  }
};

exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return sendResponse(res, 400, null, 'Please provide current and new password');
    }

    if (newPassword.length < 8) {
      return sendResponse(res, 400, null, 'New password must be at least 8 characters');
    }

    // Get user with password
    const user = await User.findById(req.user._id).select('+password');

    // Check current password
    const isPasswordValid = await user.matchPassword(currentPassword);
    
    if (!isPasswordValid) {
      return sendResponse(res, 401, null, 'Current password is incorrect');
    }

    // Update password
    user.password = newPassword;
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    const token = jwt.sign(
      { 
        id: user._id,
        role: user.role,
        permissions: user.permissions
      },
      process.env.JWT_SECRET || 'development-secret-key',
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    return sendResponse(res, 200, { 
      token,
      expiresIn: 7 * 24 * 60 * 60,
      tokenType: 'Bearer',
    }, 'Password changed successfully');
  } catch (error) {
    handleError(res, error, 'Failed to change password');
  }
};

exports.logout = async (req, res) => {
  try {
    return sendResponse(res, 200, null, 'Logged out successfully');
  } catch (error) {
    handleError(res, error, 'Logout failed');
  }
};

// ==================== ADMIN CONTROLLERS ====================

exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find({ isDeleted: false })
      .select('-password -loginAttempts -lockUntil -passwordResetToken -passwordResetExpires')
      .sort({ createdAt: -1 });
    
    return sendResponse(res, 200, { users }, 'Users retrieved successfully');
  } catch (error) {
    handleError(res, error, 'Failed to retrieve users');
  }
};

exports.getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -loginAttempts -lockUntil -passwordResetToken -passwordResetExpires');
    
    if (!user) {
      return sendResponse(res, 404, null, 'User not found');
    }
    
    return sendResponse(res, 200, { user }, 'User retrieved successfully');
  } catch (error) {
    handleError(res, error, 'Failed to retrieve user');
  }
};

exports.updateUser = async (req, res) => {
  try {
    const { name, email, role, isActive } = req.body;
    
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return sendResponse(res, 404, null, 'User not found');
    }
    
    // Prevent admins from modifying superadmins
    if (user.role === 'superadmin' && req.user.role !== 'superadmin') {
      return sendResponse(res, 403, null, 'Only superadmin can modify superadmin users');
    }
    
    // Prevent changing own role
    if (req.params.id === req.user.id && role && role !== req.user.role) {
      return sendResponse(res, 400, null, 'Cannot change your own role');
    }
    
    const updateData = {};
    if (name) updateData.name = name.trim();
    if (email && email !== user.email) {
      const emailExists = await User.findOne({ email: email.toLowerCase().trim(), _id: { $ne: user._id } });
      if (emailExists) {
        return sendResponse(res, 409, null, 'Email already in use');
      }
      updateData.email = email.toLowerCase().trim();
    }
    if (role && ['user', 'admin', 'superadmin'].includes(role)) {
      updateData.role = role;
    }
    if (isActive !== undefined) {
      updateData.isActive = isActive;
    }
    
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');
    
    return sendResponse(res, 200, { user: updatedUser }, 'User updated successfully');
  } catch (error) {
    handleError(res, error, 'Failed to update user');
  }
};

exports.deleteUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return sendResponse(res, 404, null, 'User not found');
    }
    
    // Prevent deleting self
    if (req.params.id === req.user.id) {
      return sendResponse(res, 400, null, 'Cannot delete your own account');
    }
    
    // Prevent deleting superadmin unless you're superadmin
    if (user.role === 'superadmin' && req.user.role !== 'superadmin') {
      return sendResponse(res, 403, null, 'Only superadmin can delete superadmin users');
    }
    
    // Soft delete
    user.isDeleted = true;
    user.isActive = false;
    await user.save();
    
    return sendResponse(res, 200, null, 'User deleted successfully');
  } catch (error) {
    handleError(res, error, 'Failed to delete user');
  }
};

// ==================== PERMISSION MANAGEMENT ====================

exports.assignPermissions = async (req, res) => {
  try {
    const { permissions } = req.body;
    
    if (!permissions || !Array.isArray(permissions)) {
      return sendResponse(res, 400, null, 'Permissions array is required');
    }
    
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return sendResponse(res, 404, null, 'User not found');
    }
    
    // Validate permissions
    const validPermissions = [
      'view_profile', 'update_profile', 'change_password',
      'view_users', 'create_users', 'update_users', 'delete_users',
      'view_roles', 'create_roles', 'update_roles', 'delete_roles',
      'view_permissions', 'assign_permissions',
      'manage_all'
    ];
    
    const invalidPermissions = permissions.filter(p => !validPermissions.includes(p));
    if (invalidPermissions.length > 0) {
      return sendResponse(res, 400, null, `Invalid permissions: ${invalidPermissions.join(', ')}`);
    }
    
    // REPLACE all permissions (current behavior)
    user.permissions = permissions;
    await user.save();
    
    const userResponse = user.toObject();
    delete userResponse.password;
    
    return sendResponse(res, 200, { 
      user: userResponse,
      message: `All permissions replaced. User now has ${permissions.length} permission(s).`
    }, 'Permissions assigned successfully');
  } catch (error) {
    handleError(res, error, 'Failed to assign permissions');
  }
};

// NEW: Add specific permissions
exports.addPermissions = async (req, res) => {
  try {
    const { permissions } = req.body;
    
    if (!permissions || !Array.isArray(permissions)) {
      return sendResponse(res, 400, null, 'Permissions array is required');
    }
    
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return sendResponse(res, 404, null, 'User not found');
    }
    
    // Validate permissions
    const validPermissions = [
      'view_profile', 'update_profile', 'change_password',
      'view_users', 'create_users', 'update_users', 'delete_users',
      'view_roles', 'create_roles', 'update_roles', 'delete_roles',
      'view_permissions', 'assign_permissions',
      'manage_all'
    ];
    
    const invalidPermissions = permissions.filter(p => !validPermissions.includes(p));
    if (invalidPermissions.length > 0) {
      return sendResponse(res, 400, null, `Invalid permissions: ${invalidPermissions.join(', ')}`);
    }
    
    // Get current permissions
    const currentPermissions = user.permissions || [];
    
    // Add new permissions (avoid duplicates)
    const newPermissions = [...currentPermissions];
    permissions.forEach(permission => {
      if (!newPermissions.includes(permission)) {
        newPermissions.push(permission);
      }
    });
    
    // Update user with combined permissions
    user.permissions = newPermissions;
    await user.save();
    
    const userResponse = user.toObject();
    delete userResponse.password;
    
    return sendResponse(res, 200, { 
      user: userResponse,
      addedPermissions: permissions,
      totalPermissions: user.permissions.length,
      message: `Added ${permissions.length} permission(s). User now has ${user.permissions.length} permission(s).`
    }, 'Permissions added successfully');
  } catch (error) {
    handleError(res, error, 'Failed to add permissions');
  }
};

// NEW: Remove specific permissions
exports.removePermissions = async (req, res) => {
  try {
    const { permissions } = req.body;
    
    if (!permissions || !Array.isArray(permissions)) {
      return sendResponse(res, 400, null, 'Permissions array is required');
    }
    
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return sendResponse(res, 404, null, 'User not found');
    }
    
    // Validate permissions
    const validPermissions = [
      'view_profile', 'update_profile', 'change_password',
      'view_users', 'create_users', 'update_users', 'delete_users',
      'view_roles', 'create_roles', 'update_roles', 'delete_roles',
      'view_permissions', 'assign_permissions',
      'manage_all'
    ];
    
    const invalidPermissions = permissions.filter(p => !validPermissions.includes(p));
    if (invalidPermissions.length > 0) {
      return sendResponse(res, 400, null, `Invalid permissions: ${invalidPermissions.join(', ')}`);
    }
    
    // Get current permissions
    const currentPermissions = user.permissions || [];
    
    // Remove specified permissions
    const newPermissions = currentPermissions.filter(p => !permissions.includes(p));
    
    // Update user with filtered permissions
    user.permissions = newPermissions;
    await user.save();
    
    const userResponse = user.toObject();
    delete userResponse.password;
    
    return sendResponse(res, 200, { 
      user: userResponse,
      removedPermissions: permissions,
      totalPermissions: user.permissions.length,
      message: `Removed ${permissions.length} permission(s). User now has ${user.permissions.length} permission(s).`
    }, 'Permissions removed successfully');
  } catch (error) {
    handleError(res, error, 'Failed to remove permissions');
  }
};

// NEW: Get user's current permissions
exports.getUserPermissions = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('permissions role');
    
    if (!user) {
      return sendResponse(res, 404, null, 'User not found');
    }
    
    return sendResponse(res, 200, { 
      userId: user._id,
      role: user.role,
      permissions: user.permissions,
      totalPermissions: user.permissions.length
    }, 'User permissions retrieved');
  } catch (error) {
    handleError(res, error, 'Failed to get user permissions');
  }
};

// NEW: Reset to default permissions based on role
exports.resetPermissions = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return sendResponse(res, 404, null, 'User not found');
    }
    
    let defaultPermissions = [];
    
    // Set default permissions based on role
    switch (user.role) {
      case 'user':
        defaultPermissions = ['view_profile', 'update_profile', 'change_password'];
        break;
      case 'admin':
        defaultPermissions = [
          'view_profile', 'update_profile', 'change_password',
          'view_users', 'create_users', 'update_users', 'view_roles'
        ];
        break;
      case 'superadmin':
        defaultPermissions = ['manage_all'];
        break;
      default:
        defaultPermissions = ['view_profile', 'update_profile', 'change_password'];
    }
    
    user.permissions = defaultPermissions;
    await user.save();
    
    const userResponse = user.toObject();
    delete userResponse.password;
    
    return sendResponse(res, 200, { 
      user: userResponse,
      resetTo: defaultPermissions,
      message: `Permissions reset to default for ${user.role} role.`
    }, 'Permissions reset successfully');
  } catch (error) {
    handleError(res, error, 'Failed to reset permissions');
  }
};