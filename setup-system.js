const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

console.log('🚀 Setting up Complete System...\n');

async function setupSystem() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/yaob_db');
    console.log('✅ Connected to MongoDB');

    // Import models
    const Permission = require('./models/permission.model');
    const Role = require('./models/role.model');
    const User = require('./models/user.model');

    // Step 1: Clear existing data
    console.log('🗑️  Clearing existing data...');
    await Permission.deleteMany({});
    await Role.deleteMany({});
    await User.deleteMany({ email: { $ne: 'admin@example.com' } });
    console.log('✅ Data cleared');

    // Step 2: Create permissions
    console.log('\n📋 Creating permissions...');
    const permissions = [
      // User Management
      { name: 'view_users', description: 'Can view all users', category: 'user_management', module: 'users' },
      { name: 'create_user', description: 'Can create new users', category: 'user_management', module: 'users' },
      { name: 'update_user', description: 'Can update user information', category: 'user_management', module: 'users' },
      { name: 'delete_user', description: 'Can delete users', category: 'user_management', module: 'users' },
      { name: 'restore_user', description: 'Can restore deleted users', category: 'user_management', module: 'users' },
      { name: 'view_self', description: 'Can view own profile', category: 'user_management', module: 'users', isDefault: true },

      // Role Management
      { name: 'view_roles', description: 'Can view all roles', category: 'role_management', module: 'roles' },
      { name: 'create_role', description: 'Can create new roles', category: 'role_management', module: 'roles' },
      { name: 'update_role', description: 'Can update roles', category: 'role_management', module: 'roles' },
      { name: 'archive_role', description: 'Can archive/delete roles', category: 'role_management', module: 'roles' },

      // Permission Management
      { name: 'view_permissions', description: 'Can view all permissions', category: 'permission_management', module: 'permissions' },
      { name: 'create_permission', description: 'Can create new permissions', category: 'permission_management', module: 'permissions' },
      { name: 'update_permission', description: 'Can update permissions', category: 'permission_management', module: 'permissions' },
      { name: 'delete_permission', description: 'Can delete permissions', category: 'permission_management', module: 'permissions' },

      // Add more permissions as needed...
    ];

    const createdPermissions = await Permission.insertMany(permissions);
    console.log(`✅ Created ${createdPermissions.length} permissions`);

    // Step 3: Create roles with permissions
    console.log('\n👑 Creating roles...');
    
    // Create Admin role with all permissions
    const adminRole = await Role.create({
      name: 'Admin',
      description: 'System Administrator with full access',
      permissions: createdPermissions.map(perm => ({
        permissionId: perm._id,
        name: perm.name
      })),
      hierarchyLevel: 10,
      isDefault: false,
      isActive: true
    });

    // Create User role with basic permissions
    const userPermissions = createdPermissions.filter(p => 
      ['view_self'].includes(p.name)
    );
    
    const userRole = await Role.create({
      name: 'User',
      description: 'Regular user with basic access',
      permissions: userPermissions.map(perm => ({
        permissionId: perm._id,
        name: perm.name
      })),
      hierarchyLevel: 1,
      isDefault: true,
      isActive: true
    });

    console.log(`✅ Created roles: ${adminRole.name}, ${userRole.name}`);

    // Step 4: Update existing admin user with Admin role
    console.log('\n👤 Updating admin user...');
    const existingAdmin = await User.findOne({ email: 'admin@example.com' });
    
    if (existingAdmin) {
      // Get permission names for Admin role
      const adminPermissionNames = createdPermissions.map(p => p.name);
      
      // Update admin user with Admin role
      existingAdmin.roles = [{
        roleId: adminRole._id,
        name: adminRole.name,
        permissions: adminPermissionNames
      }];
      existingAdmin.permissions = adminPermissionNames;
      await existingAdmin.save();
      
      console.log(`✅ Updated admin user with ${adminPermissionNames.length} permissions`);
    } else {
      // Create new admin if doesn't exist
      const salt = await bcrypt.genSalt(12);
      const hashedPassword = await bcrypt.hash('Admin123!', salt);
      
      const adminPermissionNames = createdPermissions.map(p => p.name);
      
      await User.create({
        name: 'System Administrator',
        email: 'admin@example.com',
        password: hashedPassword,
        roles: [{
          roleId: adminRole._id,
          name: adminRole.name,
          permissions: adminPermissionNames
        }],
        permissions: adminPermissionNames,
        isActive: true
      });
      
      console.log('✅ Created new admin user');
    }

    // Step 5: Create test user
    console.log('\n👤 Creating test user...');
    const testUser = await User.create({
      name: 'Test User',
      email: 'test@example.com',
      password: 'Test123!',
      roles: [{
        roleId: userRole._id,
        name: userRole.name,
        permissions: userPermissions.map(p => p.name)
      }],
      permissions: userPermissions.map(p => p.name),
      isActive: true
    });

    console.log('✅ Created test user: test@example.com / Test123!');

    // Summary
    console.log('\n🎉 SYSTEM SETUP COMPLETE!');
    console.log('=' .repeat(50));
    console.log('📋 Permissions:', createdPermissions.length);
    console.log('👑 Roles: 2 (Admin, User)');
    console.log('👥 Users:');
    console.log('  📧 admin@example.com / Admin123! (Admin role)');
    console.log('  📧 test@example.com / Test123! (User role)');
    console.log('=' .repeat(50));
    console.log('\n✅ Ready to use!');

    process.exit(0);
  } catch (error) {
    console.error('❌ Setup failed:', error.message);
    process.exit(1);
  }
}

setupSystem();