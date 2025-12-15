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
        'view_profile', 'update_profile', 'change_password',
        'view_users', 'create_users', 'update_users', 'delete_users',
        'view_roles', 'create_roles', 'update_roles', 'delete_roles',
        'view_permissions', 'assign_permissions',
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
  if (this.isDefault && this.isModified('isDefault')) {
    const defaultRoles = await this.constructor.countDocuments({ 
      isDefault: true, 
      _id: { $ne: this._id } 
    });
    if (defaultRoles === 0) {
      next(new Error('Cannot remove the last default role'));
    }
  }
  next();
});

const Role = mongoose.model('Role', roleSchema);

module.exports = Role;