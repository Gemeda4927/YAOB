require('dotenv').config();
const mongoose = require('mongoose');
const app = require('./app');

const PORT = process.env.PORT || 3000;
const ENV = process.env.NODE_ENV || 'development';

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`
=========================================
✅ MongoDB Connected
📦 Database: ${conn.connection.name}
🌐 Host: ${conn.connection.host}
=========================================
    `);
  } catch (error) {
    console.error(`
=========================================
❌ MongoDB Connection Failed
-----------------------------------------
Error: ${error.message}
Stack: ${error.stack}
=========================================
    `);
    process.exit(1);
  }
};

connectDB().then(() => {
  const server = app.listen(PORT, () => {
    console.log(`
=========================================
🚀 Server Running
🌐 URL: http://localhost:${PORT}
📍 Environment: ${ENV}
🚉 Port: ${PORT}
=========================================
    `);
  });

  process.on('unhandledRejection', (err) => {
    console.error(`
=========================================
❌ UNHANDLED PROMISE REJECTION
-----------------------------------------
Error: ${err.message}
Stack: ${err.stack}
=========================================
    `);
    server.close(() => process.exit(1));
  });

  process.on('uncaughtException', (err) => {
    console.error(`
=========================================
❌ UNCAUGHT EXCEPTION
-----------------------------------------
Error: ${err.message}
Stack: ${err.stack}
=========================================
    `);
    server.close(() => process.exit(1));
  });
});
