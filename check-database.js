const mongoose = require('mongoose');
require('dotenv').config();

async function checkDB() {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/yaob_db');
    
    const Role = require('./models/role.model');
    const Permission = require('./models/permission.model');
    const User = require('./models/user.model');
    
    console.log('🔍 DATABASE CHECK\n');
    
    // Check roles
    console.log('📋 ROLES:');
    const roles = await Role.find({}).lean();
    if (roles.length === 0) {
      console.log('  ❌ No roles found!');
    } else {
      roles.forEach(role => {
        console.log(`  👑 ${role.name}`);
        console.log(`    ID: ${role._id}`);
        console.log(`    Active: ${role.isActive}`);
        console.log(`    Default: ${role.isDefault}`);
        console.log(`    Permissions: ${role.permissions ? role.permissions.length : 0}`);
        console.log('');
      });
    }
    
    // Check permissions
    console.log('\n🔐 PERMISSIONS:');
    const permissions = await Permission.find({}).lean();
    console.log(`  Total: ${permissions.length} permissions`);
    
    // Check users
    console.log('\n👥 USERS:');
    const users = await User.find({}).lean();
    users.forEach(user => {
      console.log(`  👤 ${user.name} (${user.email})`);
      console.log(`    Roles: ${user.roles ? user.roles.map(r => r.name).join(', ') : 'None'}`);
      console.log('');
    });
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

checkDB();