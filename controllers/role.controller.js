const Role = require('../models/role.model');
const Permission = require('../models/permission.model');
const User = require('../models/user.model');
const crypto = require('crypto');

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

// Error handling utility
const handleError = (res, error, customMessage = 'An error occurred') => {
  console.error(`[${new Date().toISOString()}] Role Controller Error: ${customMessage}`, error);
  
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

// ==================== PERMISSION CONTROLLERS ====================

/**
 * @desc    Get all permissions
 * @route   GET /api/v1/roles/permissions
 * @access  Private/Admin
 */
exports.getAllPermissions = async (req, res) => {
  try {
    const { category, module, search } = req.query;
    
    const filter = { isActive: true };
    
    if (category) {
      filter.category = category;
    }
    
    if (module) {
      filter.module = module;
    }
    
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    
    const permissions = await Permission.find(filter)
      .sort({ category: 1, name: 1 })
      .select('-__v');
    
    // Group by category for better organization
    const groupedPermissions = permissions.reduce((acc, permission) => {
      if (!acc[permission.category]) {
        acc[permission.category] = [];
      }
      acc[permission.category].push(permission);
      return acc;
    }, {});
    
    return sendResponse(res, 200, {
      permissions: groupedPermissions,
      count: permissions.length,
      categories: Object.keys(groupedPermissions)
    }, 'Permissions retrieved successfully');
  } catch (error) {
    handleError(res, error, 'Failed to retrieve permissions');
  }
};

/**
 * @desc    Create a new permission
 * @route   POST /api/v1/roles/permissions
 * @access  Private/Admin
 */
exports.createPermission = async (req, res) => {
  try {
    const { name, description, category, module, isDefault } = req.body;
    
    // Validate required fields
    if (!name || !description || !category || !module) {
      return sendResponse(res, 400, null, 'Name, description, category, and module are required');
    }
    
    // Check if permission already exists
    const existingPermission = await Permission.findOne({ name });
    if (existingPermission) {
      return sendResponse(res, 409, null, `Permission "${name}" already exists`);
    }
    
    // Create permission
    const permission = await Permission.create({
      name: name.toLowerCase().trim(),
      description: description.trim(),
      category,
      module,
      isDefault: isDefault || false,
      isActive: true
    });
    
    return sendResponse(res, 201, { permission }, 'Permission created successfully');
  } catch (error) {
    handleError(res, error, 'Failed to create permission');
  }
};

// ==================== ROLE CONTROLLERS ====================

/**
 * @desc    Get all roles
 * @route   GET /api/v1/roles
 * @access  Private/Admin
 */
exports.getAllRoles = async (req, res) => {
  try {
    const { search, isActive } = req.query;
    
    const filter = {};
    
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (isActive !== undefined) {
      filter.isActive = isActive === 'true';
    }
    
    const roles = await Role.find(filter)
      .populate({
        path: 'permissions.permissionId',
        select: 'name description category module'
      })
      .sort({ hierarchyLevel: -1, name: 1 })
      .select('-__v');
    
    return sendResponse(res, 200, {
      roles,
      count: roles.length
    }, 'Roles retrieved successfully');
  } catch (error) {
    handleError(res, error, 'Failed to retrieve roles');
  }
};

/**
 * @desc    Get single role
 * @route   GET /api/v1/roles/:id
 * @access  Private/Admin
 */
exports.getRole = async (req, res) => {
  try {
    const role = await Role.findById(req.params.id)
      .populate({
        path: 'permissions.permissionId',
        select: 'name description category module'
      })
      .select('-__v');
    
    if (!role) {
      return sendResponse(res, 404, null, 'Role not found');
    }
    
    return sendResponse(res, 200, { role }, 'Role retrieved successfully');
  } catch (error) {
    handleError(res, error, 'Failed to retrieve role');
  }
};

/**
 * @desc    Create a new role
 * @route   POST /api/v1/roles
 * @access  Private/Admin
 */
exports.createRole = async (req, res) => {
  try {
    const { name, description, permissions, hierarchyLevel, isDefault } = req.body;
    
    // Validate required fields
    if (!name || !description) {
      return sendResponse(res, 400, null, 'Name and description are required');
    }
    
    // Check if role already exists
    const existingRole = await Role.findOne({ name });
    if (existingRole) {
      return sendResponse(res, 409, null, `Role "${name}" already exists`);
    }
    
    // Validate permissions if provided
    let permissionObjects = [];
    if (permissions && permissions.length > 0) {
      const permissionDocs = await Permission.find({ 
        name: { $in: permissions },
        isActive: true 
      });
      
      if (permissionDocs.length !== permissions.length) {
        return sendResponse(res, 400, null, 'Some permissions are invalid or inactive');
      }
      
      permissionObjects = permissionDocs.map(perm => ({
        permissionId: perm._id,
        name: perm.name
      }));
    }
    
    // Create role
    const role = await Role.create({
      name: name.trim(),
      description: description.trim(),
      permissions: permissionObjects,
      hierarchyLevel: hierarchyLevel || 1,
      isDefault: isDefault || false,
      isActive: true,
      createdBy: req.user._id
    });
    
    const populatedRole = await Role.findById(role._id)
      .populate({
        path: 'permissions.permissionId',
        select: 'name description category module'
      });
    
    return sendResponse(res, 201, { role: populatedRole }, 'Role created successfully');
  } catch (error) {
    handleError(res, error, 'Failed to create role');
  }
};

/**
 * @desc    Update role
 * @route   PUT /api/v1/roles/:id
 * @access  Private/Admin
 */
exports.updateRole = async (req, res) => {
  try {
    const { name, description, permissions, hierarchyLevel, isDefault, isActive } = req.body;
    
    const role = await Role.findById(req.params.id);
    if (!role) {
      return sendResponse(res, 404, null, 'Role not found');
    }
    
    // Update fields
    if (name !== undefined) role.name = name.trim();
    if (description !== undefined) role.description = description.trim();
    if (hierarchyLevel !== undefined) role.hierarchyLevel = hierarchyLevel;
    if (isDefault !== undefined) role.isDefault = isDefault;
    if (isActive !== undefined) role.isActive = isActive;
    
    // Update permissions if provided
    if (permissions !== undefined) {
      const permissionDocs = await Permission.find({ 
        name: { $in: permissions },
        isActive: true 
      });
      
      if (permissionDocs.length !== permissions.length) {
        return sendResponse(res, 400, null, 'Some permissions are invalid or inactive');
      }
      
      role.permissions = permissionDocs.map(perm => ({
        permissionId: perm._id,
        name: perm.name
      }));
    }
    
    role.updatedBy = req.user._id;
    await role.save();
    
    const populatedRole = await Role.findById(role._id)
      .populate({
        path: 'permissions.permissionId',
        select: 'name description category module'
      });
    
    return sendResponse(res, 200, { role: populatedRole }, 'Role updated successfully');
  } catch (error) {
    handleError(res, error, 'Failed to update role');
  }
};

/**
 * @desc    Delete role
 * @route   DELETE /api/v1/roles/:id
 * @access  Private/Admin
 */
exports.deleteRole = async (req, res) => {
  try {
    const role = await Role.findById(req.params.id);
    if (!role) {
      return sendResponse(res, 404, null, 'Role not found');
    }
    
    // Check if role is assigned to any user
    const usersWithRole = await User.find({ 
      'roles.roleId': role._id 
    });
    
    if (usersWithRole.length > 0) {
      return sendResponse(res, 400, null, `Cannot delete role. It is assigned to ${usersWithRole.length} user(s)`);
    }
    
    // Soft delete by marking as inactive
    role.isActive = false;
    role.updatedBy = req.user._id;
    await role.save();
    
    return sendResponse(res, 200, null, 'Role deactivated successfully');
  } catch (error) {
    handleError(res, error, 'Failed to delete role');
  }
};

/**
 * @desc    Assign role to user
 * @route   POST /api/v1/roles/:roleId/assign/:userId
 * @access  Private/Admin
 */
exports.assignRoleToUser = async (req, res) => {
  try {
    const { roleId, userId } = req.params;
    
    const role = await Role.findById(roleId);
    if (!role || !role.isActive) {
      return sendResponse(res, 404, null, 'Role not found or inactive');
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return sendResponse(res, 404, null, 'User not found');
    }
    
    // Check if user already has this role
    const alreadyHasRole = user.roles.some(r => 
      r.roleId.toString() === roleId
    );
    
    if (alreadyHasRole) {
      return sendResponse(res, 400, null, 'User already has this role');
    }
    
    // Add role to user
    user.roles.push({
      roleId: role._id,
      name: role.name,
      permissions: role.permissions.map(p => p.name)
    });
    
    // Update user permissions
    const userWithPermissions = await User.findById(user._id)
      .populate({
        path: 'roles.roleId',
        select: 'name permissions',
        populate: {
          path: 'permissions.permissionId',
          select: 'name'
        }
      });
    
    const userPermissions = userWithPermissions.getPermissions();
    user.permissions = userPermissions;
    
    await user.save();
    
    return sendResponse(res, 200, { user }, 'Role assigned successfully');
  } catch (error) {
    handleError(res, error, 'Failed to assign role');
  }
};

/**
 * @desc    Remove role from user
 * @route   DELETE /api/v1/roles/:roleId/remove/:userId
 * @access  Private/Admin
 */
exports.removeRoleFromUser = async (req, res) => {
  try {
    const { roleId, userId } = req.params;
    
    const user = await User.findById(userId);
    if (!user) {
      return sendResponse(res, 404, null, 'User not found');
    }
    
    // Check if user has this role
    const roleIndex = user.roles.findIndex(r => 
      r.roleId.toString() === roleId
    );
    
    if (roleIndex === -1) {
      return sendResponse(res, 400, null, 'User does not have this role');
    }
    
    // Remove role from user
    user.roles.splice(roleIndex, 1);
    
    // Update user permissions
    const userWithPermissions = await User.findById(user._id)
      .populate({
        path: 'roles.roleId',
        select: 'name permissions',
        populate: {
          path: 'permissions.permissionId',
          select: 'name'
        }
      });
    
    const userPermissions = userWithPermissions.getPermissions();
    user.permissions = userPermissions;
    
    await user.save();
    
    return sendResponse(res, 200, { user }, 'Role removed successfully');
  } catch (error) {
    handleError(res, error, 'Failed to remove role');
  }
};