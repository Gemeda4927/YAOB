const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Role name is required'],
      unique: true,
      trim: true,
      enum: ['user', 'admin', 'superadmin']
    },
    
    description: {
      type: String,
      trim: true,
    },
    
    permissions: [{
      type: String,
      enum: [
        // User permissions
        'view_profile', 'update_profile', 'change_password',
        
        // Admin permissions
        'view_users', 'create_users', 'update_users', 'delete_users',
        'view_roles', 'create_roles', 'update_roles', 'delete_roles',
        'view_permissions', 'assign_permissions',
        
        // EVENT PERMISSIONS (ADDED THESE 6)
        'view_events', 'create_events', 'update_events', 'delete_events',
        'manage_event_registrations', 'publish_events',
        
        // Superadmin permission
        'manage_all'
      ]
    }],
    
    isDefault: {
      type: Boolean,
      default: false,
    },
    
    isActive: {
      type: Boolean,
      default: true,
    },
    
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
  },
  {
    timestamps: true,
  }
);

// Prevent removing the last default role
roleSchema.pre('save', async function(next) {
  if (this.isModified('isDefault') && !this.isDefault) {
    const defaultRoles = await this.constructor.countDocuments({ 
      isDefault: true, 
      _id: { $ne: this._id } 
    });
    if (defaultRoles === 0) {
      return next(new Error('Cannot remove the last default role'));
    }
  }
  next();
});

// Middleware to check valid permissions
roleSchema.pre('save', function(next) {
  if (this.isModified('permissions')) {
    const validPermissions = [
      'view_profile', 'update_profile', 'change_password',
      'view_users', 'create_users', 'update_users', 'delete_users',
      'view_roles', 'create_roles', 'update_roles', 'delete_roles',
      'view_permissions', 'assign_permissions',
      'view_events', 'create_events', 'update_events', 'delete_events',
      'manage_event_registrations', 'publish_events',
      'manage_all'
    ];
    
    for (const permission of this.permissions) {
      if (!validPermissions.includes(permission)) {
        return next(new Error(`Invalid permission: ${permission}`));
      }
    }
  }
  next();
});

const Role = mongoose.model('Role', roleSchema);

module.exports = Role;