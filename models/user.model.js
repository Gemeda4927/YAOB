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
    
    role: {
      type: String,
      enum: ['user', 'admin', 'superadmin'],
      default: 'user',
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
        
        // Event permissions
        'view_events', 'create_events', 'update_events', 'delete_events',
        'manage_event_registrations', 'publish_events',
        
        // Superadmin permission
        'manage_all'
      ]
    }],
    
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
    
    passwordResetToken: String,
    passwordResetExpires: Date,
    
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
    toJSON: { 
      transform: function(doc, ret) {
        delete ret.password;
        delete ret.loginAttempts;
        delete ret.lockUntil;
        delete ret.passwordResetToken;
        delete ret.passwordResetExpires;
        return ret;
      }
    },
    toObject: {
      transform: function(doc, ret) {
        delete ret.password;
        delete ret.loginAttempts;
        delete ret.lockUntil;
        delete ret.passwordResetToken;
        delete ret.passwordResetExpires;
        return ret;
      }
    }
  }
);



userSchema.pre('save', async function () {
  // Trim email and name
  if (this.isModified('email')) {
    this.email = this.email.toLowerCase().trim();
  }

  if (this.isModified('name')) {
    this.name = this.name.trim();
  }

  // Hash password if needed
  if (
    this.isModified('password') &&
    !this.password.startsWith('$2a$') &&
    !this.password.startsWith('$2b$')
  ) {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
  }
});

// Password comparison method
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Password reset token generation
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
    
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  
  return resetToken;
};

// Permission checking methods
userSchema.methods.hasPermission = function(permission) {
  // Superadmin has all permissions
  if (this.role === 'superadmin') return true;
  
  // Check if user has manage_all permission
  if (this.permissions && this.permissions.includes('manage_all')) return true;
  
  // Check if permission exists in user's permissions array
  return this.permissions && this.permissions.includes(permission);
};

userSchema.methods.hasRole = function(role) {
  return this.role === role;
};

userSchema.methods.isAdmin = function() {
  return this.role === 'admin' || this.role === 'superadmin';
};

// Event permission methods
userSchema.methods.canViewEvents = function() {
  return this.hasPermission('view_events');
};

userSchema.methods.canCreateEvents = function() {
  return this.hasPermission('create_events');
};

userSchema.methods.canUpdateEvents = function() {
  return this.hasPermission('update_events');
};

userSchema.methods.canDeleteEvents = function() {
  return this.hasPermission('delete_events');
};

userSchema.methods.canPublishEvents = function() {
  return this.hasPermission('publish_events');
};

const User = mongoose.model('User', userSchema);

module.exports = User;