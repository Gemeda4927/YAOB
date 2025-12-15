const User = require('../models/user.model');

/**
 * Protect routes - verify JWT
 */
exports.protect = async (req, res, next) => {
  try {
    let token;
    
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        error: {
          message: 'Please log in to get access',
          code: 'UNAUTHORIZED'
        }
      });
    }

    const jwt = require('jsonwebtoken');
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'development-secret-key');
    
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: {
          message: 'User no longer exists',
          code: 'USER_NOT_FOUND'
        }
      });
    }

    if (!user.isActive || user.isDeleted) {
      return res.status(401).json({
        success: false,
        error: {
          message: 'Account has been deactivated',
          code: 'ACCOUNT_DEACTIVATED'
        }
      });
    }

    req.user = user;
    req.userId = user._id;
    req.userRole = user.role;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        error: {
          message: 'Invalid token',
          code: 'INVALID_TOKEN'
        }
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: {
          message: 'Token has expired',
          code: 'TOKEN_EXPIRED'
        }
      });
    }
    
    return res.status(500).json({
      success: false,
      error: {
        message: 'Authentication failed',
        code: 'AUTH_FAILED'
      }
    });
  }
};

/**
 * Restrict to specific roles
 */
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: {
          message: 'Authentication required',
          code: 'UNAUTHORIZED'
        }
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: {
          message: `Access restricted to: ${roles.join(', ')}`,
          code: 'ACCESS_DENIED',
          requiredRoles: roles,
          userRole: req.user.role
        }
      });
    }

    next();
  };
};

/**
 * Check for specific permission
 */
exports.hasPermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: {
          message: 'Authentication required',
          code: 'UNAUTHORIZED'
        }
      });
    }

    if (!req.user.hasPermission(permission)) {
      return res.status(403).json({
        success: false,
        error: {
          message: `Permission denied. Required: ${permission}`,
          code: 'PERMISSION_DENIED',
          requiredPermission: permission,
          userPermissions: req.user.permissions
        }
      });
    }

    next();
  };
};

/**
 * Check for any of the specified permissions
 */
exports.hasAnyPermission = (...permissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: {
          message: 'Authentication required',
          code: 'UNAUTHORIZED'
        }
      });
    }

    const hasPermission = permissions.some(permission => 
      req.user.hasPermission(permission)
    );

    if (!hasPermission) {
      return res.status(403).json({
        success: false,
        error: {
          message: `Permission denied. Required one of: ${permissions.join(', ')}`,
          code: 'PERMISSION_DENIED',
          requiredPermissions: permissions,
          userPermissions: req.user.permissions
        }
      });
    }

    next();
  };
};