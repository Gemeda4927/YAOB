const dotenv = require('dotenv');
const mongoose = require('mongoose');
const app = require('./app');

// Load environment variables FIRST
dotenv.config({ debug: process.env.NODE_ENV === 'development' });

// Validate required environment variables
const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET'];
requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    console.error(`❌ Error: ${varName} environment variable is required`);
    console.log('Current environment variables loaded:', Object.keys(process.env).length);
    process.exit(1);
  }
});

console.log('✅ Environment loaded successfully');
console.log(`📁 NODE_ENV: ${process.env.NODE_ENV}`);
console.log(`🔗 MONGO_URI: ${process.env.MONGO_URI ? 'Loaded (hidden for security)' : 'Missing'}`);

// Database connection - FIXED: Removed deprecated options
const connectDB = async () => {
  try {
    // Mongoose 6+ uses new connection string options
    const options = {
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    };
    
    console.log('🔗 Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGO_URI, options);
    
    console.log('✅ MongoDB connected successfully');
    console.log(`📊 Database: ${mongoose.connection.db.databaseName}`);
    console.log(`🏓 Ping: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
    
    // Listen for connection events
    mongoose.connection.on('connected', () => {
      console.log('📡 Mongoose connected to DB');
    });
    
    mongoose.connection.on('error', (err) => {
      console.error('❌ Mongoose connection error:', err.message);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.log('⚠️ Mongoose disconnected from DB');
    });
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.log('💡 Troubleshooting tips:');
    console.log('1. Check if MongoDB Atlas cluster is running');
    console.log('2. Verify network/IP whitelist in MongoDB Atlas');
    console.log('3. Check if password contains special characters');
    console.log('4. Try connecting with MongoDB Compass first');
    process.exit(1);
  }
};

// Graceful shutdown
const gracefulShutdown = (signal) => {
  console.log(`\n${signal} received. Starting graceful shutdown...`);
  
  server.close(() => {
    console.log('✅ HTTP server closed');
    
    mongoose.connection.close(false, () => {
      console.log('✅ MongoDB connection closed');
      process.exit(0);
    });
  });
  
  // Force shutdown after 10 seconds
  setTimeout(() => {
    console.error('❌ Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

// Connect to database and start server
const startServer = async () => {
  try {
    await connectDB();
    
    const PORT = process.env.PORT || 3000;
    const server = app.listen(PORT, () => {
      console.log(`\n🚀 Server running on port ${PORT}`);
      console.log(`📚 API Documentation: http://localhost:${PORT}/docs`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`⏰ ${new Date().toLocaleString()}`);
      console.log('='.repeat(50));
    });
    
    // Handle graceful shutdown
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
    // Handle unhandled rejections
    process.on('unhandledRejection', (err) => {
      console.error('❌ Unhandled Rejection:', err.message);
      if (process.env.NODE_ENV === 'production') {
        server.close(() => {
          process.exit(1);
        });
      }
    });
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (err) => {
      console.error('❌ Uncaught Exception:', err.message);
      process.exit(1);
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
};

// Start the server
startServer();