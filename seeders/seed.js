const mongoose = require('mongoose');
const dotenv = require('dotenv');
const User = require('../models/user.model');
const Role = require('../models/role.model');

dotenv.config();

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log('✅ MongoDB connected');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  }
};

const seedDatabase = async () => {
  try {
    // Clear existing data
    await User.deleteMany({});
    await Role.deleteMany({});
    
    console.log('🗑️  Cleared existing data');
    
    // Create default roles with ALL available permissions in enum
    const roles = [
      {
        name: 'user',
        description: 'Regular user with basic permissions',
        permissions: ['view_profile', 'update_profile', 'change_password'],
        isDefault: true,
        isActive: true,
      },
      {
        name: 'admin',
        description: 'Administrator with LIMITED initial permissions',
        permissions: [
          'view_profile', 'update_profile', 'change_password',
          'view_users', 'create_users', 'update_users', 'view_roles'
        ],
        isDefault: false,
        isActive: true,
      },
      {
        name: 'superadmin',
        description: 'Super Administrator with all permissions',
        permissions: ['manage_all'],
        isDefault: false,
        isActive: true,
      }
    ];
    
    const createdRoles = await Role.insertMany(roles);
    console.log('✅ Created default roles');
    
    // Create superadmin user
    const superadmin = await User.create({
      name: 'Super Admin',
      email: 'superadmin@example.com',
      password: 'SuperAdmin123',
      role: 'superadmin',
      permissions: ['manage_all'], // Superadmin has manage_all
      isActive: true,
    });
    
    // Create admin user with LIMITED initial permissions
    const admin = await User.create({
      name: 'Admin User',
      email: 'admin@example.com',
      password: 'Admin12345',
      role: 'admin',
      permissions: [
        'view_profile', 'update_profile', 'change_password',
        'view_users', 'create_users', 'update_users', 'view_roles'
      ],
      isActive: true,
      createdBy: superadmin._id,
    });
    
    // Create regular users
    const users = [
      {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'User12345',
        role: 'user',
        permissions: ['view_profile', 'update_profile', 'change_password'],
        isActive: true,
        createdBy: admin._id,
      },
      {
        name: 'Jane Smith',
        email: 'jane@example.com',
        password: 'User12345',
        role: 'user',
        permissions: ['view_profile', 'update_profile', 'change_password'],
        isActive: true,
        createdBy: admin._id,
      },
      {
        name: 'Bob Wilson',
        email: 'bob@example.com',
        password: 'User12345',
        role: 'user',
        permissions: ['view_profile', 'update_profile', 'change_password'],
        isActive: false, // Inactive user
        createdBy: admin._id,
      }
    ];
    
    await User.insertMany(users);
    
    console.log('✅ Database seeded successfully');
    console.log('\n📋 Created Users:');
    console.log('----------------');
    console.log('Super Admin:');
    console.log(`  Email: ${superadmin.email}`);
    console.log(`  Password: SuperAdmin123`);
    console.log(`  Role: ${superadmin.role}`);
    console.log(`  Permissions: ${superadmin.permissions.join(', ')}`);
    console.log('\nAdmin User (LIMITED PERMISSIONS):');
    console.log(`  Email: ${admin.email}`);
    console.log(`  Password: Admin12345`);
    console.log(`  Role: ${admin.role}`);
    console.log(`  Permissions: ${admin.permissions.join(', ')}`);
    console.log('\nRegular Users (Password: User12345):');
    console.log(`  john@example.com`);
    console.log(`  jane@example.com`);
    console.log(`  bob@example.com (inactive)`);
    console.log('\n🔑 Use these credentials for testing');
    console.log('\n⚠️  IMPORTANT: Admin has LIMITED permissions initially!');
    console.log('   Only Superadmin can assign additional permissions using:');
    console.log('   PATCH /api/v1/auth/users/:id/permissions');
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Seeding error:', error);
    process.exit(1);
  }
};

// Run seeder
connectDB().then(() => {
  seedDatabase();
});