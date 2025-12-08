const User = require('../models/user.model');
const Role = require('../models/role.model');
const Permission = require('../models/permission.model');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const validator = require('validator');

// Utility function to send response
const sendResponse = (res, statusCode, data = null, message = '', meta = null) => {
  const response = {
    success: statusCode >= 200 && statusCode < 300,
    message: message || (statusCode >= 200 && statusCode < 300 ? 'Success' : 'Error'),
    timestamp: new Date().toISOString(),
    requestId: crypto.randomBytes(8).toString('hex'),
  };

  if (data !== null) {
    response.data = data;
  }

  if (meta !== null) {
    response.meta = meta;
  }

  return res.status(statusCode).json(response);
};

// Error handling utility for controllers
const handleError = (res, error, customMessage = 'An error occurred') => {
  console.error(`[${new Date().toISOString()}] Controller Error: ${customMessage}`, error);
  
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

  return res.status(error.statusCode || 500).json(errorResponse);
};

// ==================== PERMISSION & ROLE MIDDLEWARE ====================

/**
 * @desc    Check if user has specific permission
 * @param   {String} permission - Required permission
 */
exports.hasPermission = (permission) => {
  return async (req, res, next) => {
    try {
      console.log(`🔐 Checking permission: ${permission}`);
      
      if (!req.user) {
        console.log('🔐 No user found in request');
        return sendResponse(res, 401, null, 'Authentication required');
      }

      // Get user with populated roles and permissions
      const user = await User.findById(req.user._id)
        .populate({
          path: 'roles.roleId',
          select: 'name permissions hierarchyLevel',
          populate: {
            path: 'permissions.permissionId',
            select: 'name'
          }
        });

      if (!user) {
        return sendResponse(res, 401, null, 'User not found');
      }

      // Aggregate permissions from all roles
      const userPermissions = new Set();
      user.roles.forEach(role => {
        if (role.roleId && role.roleId.permissions) {
          role.roleId.permissions.forEach(permission => {
            if (permission.permissionId && permission.permissionId.name) {
              userPermissions.add(permission.permissionId.name);
            }
          });
        }
      });

      const permissionsArray = Array.from(userPermissions);
      console.log(`🔐 User permissions:`, permissionsArray);
      console.log(`🔐 Required permission: ${permission}`);
      
      if (!permissionsArray.includes(permission)) {
        console.log(`🔐 Permission denied for: ${permission}`);
        return sendResponse(res, 403, null, `Insufficient permissions. Required: ${permission}`);
      }
      
      console.log(`🔐 Permission granted for: ${permission}`);
      next();
    } catch (error) {
      console.error('🔐 Permission check error:', error);
      handleError(res, error, 'Permission check failed');
    }
  };
};

/**
 * @desc    Check if user has any of the specified permissions
 * @param   {Array} permissions - Array of required permissions
 */
exports.hasAnyPermission = (permissions) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return sendResponse(res, 401, null, 'Authentication required');
      }

      // Get user with populated roles and permissions
      const user = await User.findById(req.user._id)
        .populate({
          path: 'roles.roleId',
          select: 'name permissions hierarchyLevel',
          populate: {
            path: 'permissions.permissionId',
            select: 'name'
          }
        });

      if (!user) {
        return sendResponse(res, 401, null, 'User not found');
      }

      // Aggregate permissions from all roles
      const userPermissions = new Set();
      user.roles.forEach(role => {
        if (role.roleId && role.roleId.permissions) {
          role.roleId.permissions.forEach(permission => {
            if (permission.permissionId && permission.permissionId.name) {
              userPermissions.add(permission.permissionId.name);
            }
          });
        }
      });

      const permissionsArray = Array.from(userPermissions);
      const hasPermission = permissions.some(perm => 
        permissionsArray.includes(perm)
      );
      
      if (!hasPermission) {
        return sendResponse(res, 403, null, `Insufficient permissions. Required one of: ${permissions.join(', ')}`);
      }
      
      next();
    } catch (error) {
      handleError(res, error, 'Permission check failed');
    }
  };
};

/**
 * @desc    Restrict to certain roles
 * @param   {...String} roles - Allowed roles
 */
exports.restrictTo = (...roles) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return sendResponse(res, 401, null, 'Authentication required');
      }

      // Get user with populated roles
      const user = await User.findById(req.user._id)
        .populate({
          path: 'roles.roleId',
          select: 'name'
        });

      if (!user) {
        return sendResponse(res, 401, null, 'User not found');
      }

      const userRoles = user.roles.map(r => r.roleId ? r.roleId.name : r.name);
      const hasRole = roles.some(role => userRoles.includes(role));
      
      if (!hasRole) {
        return sendResponse(res, 403, null, `Access restricted to: ${roles.join(', ')}`);
      }
      
      next();
    } catch (error) {
      handleError(res, error, 'Role check failed');
    }
  };
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

    // Validate required fields
    if (!name || !email || !password) {
      return sendResponse(res, 400, null, 'Name, email, and password are required');
    }

    // Validate email
    if (!validator.isEmail(email)) {
      return sendResponse(res, 400, null, 'Please provide a valid email address');
    }

    // Validate password length (consistent with model)
    if (password.length < 8) {
      return sendResponse(res, 400, null, 'Password must be at least 8 characters');
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return sendResponse(res, 409, null, 'Email is already registered');
    }

    // Find default role if no role specified
    let defaultRole;
    if (role) {
      defaultRole = await Role.findOne({ name: role, isActive: true });
      if (!defaultRole) {
        return sendResponse(res, 400, null, `Role "${role}" not found or inactive`);
      }
    } else {
      defaultRole = await Role.findOne({ isDefault: true, isActive: true });
      if (!defaultRole) {
        return sendResponse(res, 500, null, 'No default role configured in system');
      }
    }

    // Get role permissions
    const roleWithPermissions = await Role.findById(defaultRole._id)
      .populate({
        path: 'permissions.permissionId',
        select: 'name'
      });

    const permissionNames = roleWithPermissions.permissions.map(p => p.permissionId.name);

    // Create user with role
    const user = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password,
      roles: [{
        roleId: defaultRole._id,
        name: defaultRole.name,
        permissions: permissionNames
      }],
      permissions: permissionNames
    });

    // Generate token with roles and permissions
    const token = jwt.sign(
      { 
        id: user._id, 
        roles: [defaultRole.name],
        permissions: permissionNames
      },
      process.env.JWT_SECRET || 'development-secret-key',
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    // Remove sensitive data from response
    const userResponse = user.toObject();
    delete userResponse.password;
    delete userResponse.loginAttempts;
    delete userResponse.lockUntil;
    delete userResponse.passwordResetToken;
    delete userResponse.passwordResetExpires;

    return sendResponse(res, 201, {
      user: userResponse,
      token,
      expiresIn: 604800,
      tokenType: 'Bearer',
    }, 'Registration successful');
  } catch (error) {
    handleError(res, error, 'Failed to create user account');
  }
};

/**
 * @desc    Login user
 */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return sendResponse(res, 400, null, 'Please provide email and password');
    }

    // Validate email format
    if (!validator.isEmail(email)) {
      return sendResponse(res, 400, null, 'Please provide a valid email address');
    }

    // Find user and include password
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password');
    
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
      
      // Save without triggering pre-save hooks
      await user.save({ validateBeforeSave: false, isNew: false });
      return sendResponse(res, 401, null, 'Invalid email or password');
    }

    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    user.lastLoginAt = Date.now();

    // Get user with populated roles and permissions
    const userWithPermissions = await User.findById(user._id)
      .populate({
        path: 'roles.roleId',
        select: 'name permissions',
        populate: {
          path: 'permissions.permissionId',
          select: 'name'
        }
      });

    // Aggregate permissions from all roles
    const userPermissions = new Set();
    userWithPermissions.roles.forEach(role => {
      if (role.roleId && role.roleId.permissions) {
        role.roleId.permissions.forEach(permission => {
          if (permission.permissionId && permission.permissionId.name) {
            userPermissions.add(permission.permissionId.name);
          }
        });
      }
    });

    const permissionsArray = Array.from(userPermissions);
    const userRoles = userWithPermissions.roles.map(r => r.roleId ? r.roleId.name : r.name);

    // Update user with aggregated permissions
    user.permissions = permissionsArray;
    await user.save({ validateBeforeSave: false, isNew: false });

    // Generate token with roles and permissions
    const token = jwt.sign(
      { 
        id: user._id, 
        roles: userRoles,
        permissions: permissionsArray
      },
      process.env.JWT_SECRET || 'development-secret-key',
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    // Remove sensitive data
    const userResponse = userWithPermissions.toObject();
    delete userResponse.password;
    delete userResponse.loginAttempts;
    delete userResponse.lockUntil;
    delete userResponse.passwordResetToken;
    delete userResponse.passwordResetExpires;

    return sendResponse(res, 200, {
      message: 'Login successful',
      token,
      user: {
        id: userResponse._id,
        name: userResponse.name,
        email: userResponse.email,
        roles: userRoles,
        permissions: permissionsArray
      },
      expiresIn: 7 * 24 * 60 * 60,
      tokenType: 'Bearer',
    }, 'Login successful');
  } catch (error) {
    console.error('Login error details:', error);
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
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return sendResponse(res, 401, null, 'You are not logged in. Please log in to get access.');
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'development-secret-key');

    // Check if user still exists
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return sendResponse(res, 401, null, 'The user belonging to this token no longer exists.');
    }

    // Check if user is active
    if (!user.isActive || user.isDeleted) {
      return sendResponse(res, 401, null, 'Your account has been deactivated.');
    }

    // Add user info to request
    req.user = user;
    req.userRoles = decoded.roles || [];
    req.userPermissions = decoded.permissions || [];
    
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return sendResponse(res, 401, null, 'Invalid token. Please log in again.');
    }
    
    if (error.name === 'TokenExpiredError') {
      return sendResponse(res, 401, null, 'Your token has expired. Please log in again.');
    }
    
    // For unexpected errors in middleware
    return sendResponse(res, 500, null, 'Authentication failed due to server error');
  }
};

/**
 * @desc    Get current user profile
 * @route   GET /api/v1/auth/me
 * @access  Private
 */
exports.getMe = async (req, res) => {
  try {
    // Get user with populated roles and permissions
    const userWithPermissions = await User.findById(req.user._id)
      .populate({
        path: 'roles.roleId',
        select: 'name permissions',
        populate: {
          path: 'permissions.permissionId',
          select: 'name'
        }
      });

    // Aggregate permissions from all roles
    const userPermissions = new Set();
    userWithPermissions.roles.forEach(role => {
      if (role.roleId && role.roleId.permissions) {
        role.roleId.permissions.forEach(permission => {
          if (permission.permissionId && permission.permissionId.name) {
            userPermissions.add(permission.permissionId.name);
          }
        });
      }
    });

    const permissionsArray = Array.from(userPermissions);
    const userRoles = userWithPermissions.roles.map(r => r.roleId ? r.roleId.name : r.name);

    const userResponse = userWithPermissions.toObject();
    delete userResponse.password;
    delete userResponse.loginAttempts;
    delete userResponse.lockUntil;
    delete userResponse.passwordResetToken;
    delete userResponse.passwordResetExpires;

    // Add roles and permissions to response
    userResponse.roles = userRoles;
    userResponse.permissions = permissionsArray;
    
    return sendResponse(res, 200, { user: userResponse }, 'Profile retrieved successfully');
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

    // Validate email
    if (!validator.isEmail(email)) {
      return sendResponse(res, 400, null, 'Please provide a valid email address');
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    
    if (!user) {
      // For security, don't reveal if email exists
      return sendResponse(res, 200, null, 'If your email is registered, you will receive a password reset link');
    }

    // Check if account is active
    if (!user.isActive || user.isDeleted) {
      return sendResponse(res, 400, null, 'Account is deactivated');
    }

    // Generate reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    return sendResponse(res, 200, {
      message: 'Password reset email sent',
      resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined,
      expiresIn: 600, // 10 minutes
    }, 'If your email is registered, you will receive a password reset link');
  } catch (error) {
    console.error('Forgot password error:', error);
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

    // Validate password length (consistent with model)
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

    // Get user with populated roles and permissions
    const userWithPermissions = await User.findById(user._id)
      .populate({
        path: 'roles.roleId',
        select: 'name permissions',
        populate: {
          path: 'permissions.permissionId',
          select: 'name'
        }
      });

    // Aggregate permissions from all roles
    const userPermissions = new Set();
    userWithPermissions.roles.forEach(role => {
      if (role.roleId && role.roleId.permissions) {
        role.roleId.permissions.forEach(permission => {
          if (permission.permissionId && permission.permissionId.name) {
            userPermissions.add(permission.permissionId.name);
          }
        });
      }
    });

    const permissionsArray = Array.from(userPermissions);
    const userRoles = userWithPermissions.roles.map(r => r.roleId ? r.roleId.name : r.name);

    // Update password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    
    // Generate new token with roles and permissions
    const token = jwt.sign(
      { 
        id: user._id, 
        roles: userRoles,
        permissions: permissionsArray
      },
      process.env.JWT_SECRET || 'development-secret-key',
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
    
    await user.save();

    // Remove sensitive data
    const userResponse = userWithPermissions.toObject();
    delete userResponse.password;
    delete userResponse.loginAttempts;
    delete userResponse.lockUntil;
    delete userResponse.passwordResetToken;
    delete userResponse.passwordResetExpires;

    return sendResponse(res, 200, {
      user: userResponse,
      token,
      expiresIn: 7 * 24 * 60 * 60,
      tokenType: 'Bearer',
    }, 'Password has been reset successfully');
  } catch (error) {
    console.error('Reset password error:', error);
    handleError(res, error, 'Failed to reset password');
  }
};

/**
 * @desc    Update user profile
 * @route   PATCH /api/v1/auth/update-profile
 * @access  Private
 */
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

    // Get updated user with permissions
    const userWithPermissions = await User.findById(user._id)
      .populate({
        path: 'roles.roleId',
        select: 'name permissions',
        populate: {
          path: 'permissions.permissionId',
          select: 'name'
        }
      });

    const userResponse = userWithPermissions.toObject();
    delete userResponse.password;
    delete userResponse.loginAttempts;
    delete userResponse.lockUntil;
    delete userResponse.passwordResetToken;
    delete userResponse.passwordResetExpires;

    return sendResponse(res, 200, { user: userResponse }, 'Profile updated successfully');
  } catch (error) {
    handleError(res, error, 'Failed to update profile');
  }
};

/**
 * @desc    Change password
 * @route   PATCH /api/v1/auth/change-password
 * @access  Private
 */
exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return sendResponse(res, 400, null, 'Please provide current and new password');
    }

    // Validate new password length
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

    // Get user with populated roles and permissions
    const userWithPermissions = await User.findById(user._id)
      .populate({
        path: 'roles.roleId',
        select: 'name permissions',
        populate: {
          path: 'permissions.permissionId',
          select: 'name'
        }
      });

    // Aggregate permissions from all roles
    const userPermissions = new Set();
    userWithPermissions.roles.forEach(role => {
      if (role.roleId && role.roleId.permissions) {
        role.roleId.permissions.forEach(permission => {
          if (permission.permissionId && permission.permissionId.name) {
            userPermissions.add(permission.permissionId.name);
          }
        });
      }
    });

    const permissionsArray = Array.from(userPermissions);
    const userRoles = userWithPermissions.roles.map(r => r.roleId ? r.roleId.name : r.name);

    // Update password
    user.password = newPassword;
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    // Generate new token with roles and permissions
    const token = jwt.sign(
      { 
        id: user._id, 
        roles: userRoles,
        permissions: permissionsArray
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

/**
 * @desc    Logout user (client-side - just returns success)
 * @route   POST /api/v1/auth/logout
 * @access  Private
 */
exports.logout = async (req, res) => {
  try {
    return sendResponse(res, 200, null, 'Logged out successfully');
  } catch (error) {
    handleError(res, error, 'Logout failed');
  }
};