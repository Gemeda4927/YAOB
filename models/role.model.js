const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Role name is required'],
      unique: true,
      trim: true,
      maxlength: [50, 'Role name cannot exceed 50 characters']
    },
    
    description: {
      type: String,
      required: [true, 'Role description is required'],
      trim: true,
      maxlength: [200, 'Description cannot exceed 200 characters']
    },
    
    permissions: [
      {
        permissionId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'Permission',
          required: true
        },
        name: {
          type: String,
          required: true
        }
      }
    ],
    
    hierarchyLevel: {
      type: Number,
      required: true,
      default: 1,
      min: [1, 'Hierarchy level must be at least 1'],
      max: [10, 'Hierarchy level cannot exceed 10']
    },
    
    isDefault: {
      type: Boolean,
      default: false
    },
    
    isActive: {
      type: Boolean,
      default: true
    },
    
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// Virtual for permissions names array
roleSchema.virtual('permissionNames').get(function() {
  return this.permissions.map(p => p.name);
});

// Index for faster queries
roleSchema.index({ name: 1 });
roleSchema.index({ hierarchyLevel: -1 });
roleSchema.index({ isActive: 1 });
roleSchema.index({ isDefault: 1 });

const Role = mongoose.model('Role', roleSchema);

module.exports = Role;