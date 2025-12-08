const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

async function resetAdminPassword() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/yaob_db');
    console.log('✅ Connected to MongoDB');

    // Import User model
    const User = require('./models/user.model');

    // Find the admin user
    const adminUser = await User.findOne({ email: 'admin@example.com' });
    
    if (!adminUser) {
      console.error('❌ Admin user not found!');
      process.exit(1);
    }

    console.log(`👤 Found admin user: ${adminUser.name}`);
    console.log(`📧 Email: ${adminUser.email}`);

    // Hash the password properly
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash('Admin123!', salt);

    // Update the password
    adminUser.password = hashedPassword;
    await adminUser.save();

    console.log('\n✅ Admin password reset successfully!');
    console.log('📧 Email: admin@example.com');
    console.log('🔑 New Password: Admin123!');
    console.log('\n⚠️  Test login now...');

    // Test login
    const isMatch = await bcrypt.compare('Admin123!', adminUser.password);
    console.log(`🔐 Password verification: ${isMatch ? '✅ PASS' : '❌ FAIL'}`);

    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

resetAdminPassword();