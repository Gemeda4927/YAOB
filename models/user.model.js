const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const validator = require('validator');

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please provide your name'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters'],
      maxlength: [100, 'Name cannot exceed 100 characters'],
    },
    
    email: {
      type: String,
      required: [true, 'Please provide your email'],
      unique: true,
      lowercase: true,
      trim: true,
      validate: {
        validator: validator.isEmail,
        message: 'Please provide a valid email address',
      },
    },
    
    password: {
      type: String,
      required: [true, 'Please provide a password'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false,
    },
    
    // Remove single role field, use roles array instead
    roles: [
      {
        roleId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'Role'
        },
        name: String, // Role name for quick access
        permissions: [String] // Permissions from this role
      }
    ],
    
    // Aggregated permissions from all roles (for quick access)
    permissions: [String],
    
    passwordResetToken: String,
    passwordResetExpires: Date,
    
    isActive: {
      type: Boolean,
      default: true,
    },
    
    isDeleted: {
      type: Boolean,
      default: false,
    },
    
    loginAttempts: {
      type: Number,
      default: 0,
    },
    
    lockUntil: {
      type: Date,
    },
    
    lastLoginAt: {
      type: Date,
    },
  },
  {
    timestamps: true,
    toJSON: { 
      virtuals: true,
      transform: function(doc, ret) {
        delete ret.password;
        delete ret.loginAttempts;
        delete ret.lockUntil;
        delete ret.passwordResetToken;
        delete ret.passwordResetExpires;
        // Add roles and permissions to response
        ret.roles = doc.roles.map(r => r.name);
        ret.permissions = doc.permissions || [];
        return ret;
      }
    },
    toObject: {
      virtuals: true,
      transform: function(doc, ret) {
        delete ret.password;
        delete ret.loginAttempts;
        delete ret.lockUntil;
        delete ret.passwordResetToken;
        delete ret.passwordResetExpires;
        // Add roles and permissions to response
        ret.roles = doc.roles.map(r => r.name);
        ret.permissions = doc.permissions || [];
        return ret;
      }
    }
  }
);

// FIXED: Simplified pre-save middleware
userSchema.pre('save', async function() {
  // Trim email and name
  if (this.isModified('email')) {
    this.email = this.email.toLowerCase().trim();
  }
  
  if (this.isModified('name')) {
    this.name = this.name.trim();
  }
  
  // Only hash password if it's modified (and not already hashed)
  if (this.isModified('password') && !this.password.startsWith('$2a$') && !this.password.startsWith('$2b$')) {
    try {
      const salt = await bcrypt.genSalt(12);
      this.password = await bcrypt.hash(this.password, salt);
    } catch (error) {
      throw error;
    }
  }
});

// Instance method to check password
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Instance method to create password reset token
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
    
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  return resetToken;
};

// Method to aggregate permissions from all roles
userSchema.methods.getPermissions = function() {
  const allPermissions = new Set();
  this.roles.forEach(role => {
    if (role.permissions && Array.isArray(role.permissions)) {
      role.permissions.forEach(permission => {
        allPermissions.add(permission);
      });
    }
  });
  return Array.from(allPermissions);
};

// Virtual property for isLocked
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

const User = mongoose.model('User', userSchema);

module.exports = User;