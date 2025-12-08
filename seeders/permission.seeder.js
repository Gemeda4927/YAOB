const mongoose = require('mongoose');
const Permission = require('../models/permission.model');
const Role = require('../models/role.model');
require('dotenv').config();

const permissions = [
  // User Management
  { name: 'view_users', description: 'Can view all users', category: 'user_management', module: 'users', isDefault: true },
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
  
  // Announcement Management (from your example)
  { name: 'create_announcement', description: 'Can create announcements', category: 'announcement_management', module: 'announcements' },
  { name: 'view_announcements', description: 'Can view announcements', category: 'announcement_management', module: 'announcements', isDefault: true },
  { name: 'update_announcement', description: 'Can update announcements', category: 'announcement_management', module: 'announcements' },
  { name: 'delete_announcement', description: 'Can delete announcements', category: 'announcement_management', module: 'announcements' },
  { name: 'restore_announcement', description: 'Can restore deleted announcements', category: 'announcement_management', module: 'announcements' },
  
  // Add more permissions from your example as needed...
];

const roles = [
  {
    name: 'Super Admin',
    description: 'Full system access with all permissions',
    hierarchyLevel: 10,
    isDefault: false,
    permissions: [] // Will be populated with all permissions
  },
  {
    name: 'Admin',
    description: 'Administrative access with most permissions',
    hierarchyLevel: 8,
    isDefault: false,
    permissions: [
      'view_users', 'create_user', 'update_user', 'delete_user', 'restore_user',
      'view_roles', 'create_role', 'update_role', 'archive_role',
      'view_permissions', 'create_permission', 'update_permission', 'delete_permission',
      'create_announcement', 'view_announcements', 'update_announcement', 'delete_announcement', 'restore_announcement'
      // Add more permissions as needed
    ]
  },
  {
    name: 'User',
    description: 'Regular user with basic permissions',
    hierarchyLevel: 1,
    isDefault: true,
    permissions: [
      'view_self', 'view_announcements'
    ]
  }
];

const seedDatabase = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/yourdb');
    console.log('Connected to MongoDB');
    
    // Clear existing data
    await Permission.deleteMany({});
    await Role.deleteMany({});
    console.log('Cleared existing data');
    
    // Insert permissions
    const createdPermissions = await Permission.insertMany(permissions);
    console.log(`Inserted ${createdPermissions.length} permissions`);
    
    // Create permission map for easy lookup
    const permissionMap = {};
    createdPermissions.forEach(perm => {
      permissionMap[perm.name] = perm._id;
    });
    
    // Insert roles with permission IDs
    const rolesToInsert = roles.map(role => ({
      ...role,
      permissions: role.permissions.map(permName => ({
        permissionId: permissionMap[permName],
        name: permName
      })).filter(p => p.permissionId) // Filter out permissions that weren't found
    }));
    
    // Super Admin gets all permissions
    const superAdminRole = rolesToInsert.find(r => r.name === 'Super Admin');
    if (superAdminRole) {
      superAdminRole.permissions = createdPermissions.map(perm => ({
        permissionId: perm._id,
        name: perm.name
      }));
    }
    
    const createdRoles = await Role.insertMany(rolesToInsert);
    console.log(`Inserted ${createdRoles.length} roles`);
    
    console.log('Database seeding completed successfully!');
    process.exit(0);
  } catch (error) {
    console.error('Error seeding database:', error);
    process.exit(1);
  }
};

seedDatabase();