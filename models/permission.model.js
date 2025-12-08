const mongoose = require('mongoose');

const permissionSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Permission name is required'],
      unique: true,
      trim: true,
      lowercase: true,
      match: [/^[a-z_]+$/, 'Permission name can only contain lowercase letters and underscores']
    },
    
    description: {
      type: String,
      required: [true, 'Permission description is required'],
      trim: true,
      maxlength: [200, 'Description cannot exceed 200 characters']
    },
    
    category: {
      type: String,
      required: [true, 'Category is required'],
      enum: [
        'user_management',
        'role_management', 
        'permission_management',
        'announcement_management',
        'employee_management',
        'office_management',
        'letter_management',
        'attendance_management',
        'file_management',
        'committee_management',
        'report_management',
        'appointment_management',
        'dashboard_management',
        'system_management'
      ]
    },
    
    module: {
      type: String,
      required: [true, 'Module is required'],
      enum: [
        'users',
        'roles',
        'permissions',
        'announcements',
        'employees',
        'offices',
        'letters',
        'attendance',
        'files',
        'committees',
        'reports',
        'appointments',
        'dashboard',
        'system'
      ]
    },
    
    isActive: {
      type: Boolean,
      default: true
    },
    
    isDefault: {
      type: Boolean,
      default: false
    }
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// Index for faster queries
permissionSchema.index({ name: 1 });
permissionSchema.index({ category: 1 });
permissionSchema.index({ module: 1 });
permissionSchema.index({ isActive: 1 });

const Permission = mongoose.model('Permission', permissionSchema);

module.exports = Permission;