const dotenv = require('dotenv');
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const app = require('./app');

// ==================== CONFIGURATION ====================

// Load environment variables
dotenv.config();

// Validate required environment variables
const requiredEnvVars = [
  'MONGO_URI',
  'JWT_SECRET',
  'NODE_ENV'
];

const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars.join(', '));
  process.exit(1);
}

// Security check for development JWT secret
if (process.env.NODE_ENV === 'production' && 
    process.env.JWT_SECRET === 'your-super-secret-jwt-key-change-this-in-production') {
  console.error('❌ CRITICAL: Change JWT_SECRET in production!');
  process.exit(1);
}

// ==================== LOGGER SETUP ====================

const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

const logger = {
  info: (message, meta = {}) => {
    const log = `[${new Date().toISOString()}] INFO: ${message} ${JSON.stringify(meta)}`;
    console.log(log);
    fs.appendFileSync(path.join(logDir, 'app.log'), log + '\n');
  },
  
  error: (message, error = {}, meta = {}) => {
    const log = `[${new Date().toISOString()}] ERROR: ${message} ${JSON.stringify({
      error: error.message,
      stack: error.stack,
      ...meta
    })}`;
    console.error(log);
    fs.appendFileSync(path.join(logDir, 'error.log'), log + '\n');
    
    // In production, could send to monitoring service (Sentry, etc.)
  },
  
  warn: (message, meta = {}) => {
    const log = `[${new Date().toISOString()}] WARN: ${message} ${JSON.stringify(meta)}`;
    console.warn(log);
    fs.appendFileSync(path.join(logDir, 'app.log'), log + '\n');
  }
};

// ==================== DATABASE CONNECTION ====================

const connectDB = async () => {
  try {
    const options = {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      minPoolSize: 5,
      connectTimeoutMS: 10000,
      retryWrites: true,
      w: 'majority'
    };

    logger.info('Connecting to MongoDB...', { uri: process.env.MONGO_URI ? 'loaded' : 'missing' });
    
    await mongoose.connect(process.env.MONGO_URI, options);
    
    logger.info('✅ MongoDB connected successfully', {
      db: mongoose.connection.db.databaseName,
      host: mongoose.connection.host,
      port: mongoose.connection.port,
      readyState: mongoose.connection.readyState
    });

    // Database event listeners
    mongoose.connection.on('connected', () => {
      logger.info('📡 Mongoose connected to DB');
    });
    
    mongoose.connection.on('error', (err) => {
      logger.error('Mongoose connection error', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      logger.warn('⚠️ Mongoose disconnected from DB');
    });
    
    mongoose.connection.on('reconnected', () => {
      logger.info('🔄 Mongoose reconnected to DB');
    });
    
  } catch (error) {
    logger.error('❌ MongoDB connection failed', error, {
      attempt: 1,
      timeout: 10000
    });
    
    // Retry logic for production
    if (process.env.NODE_ENV === 'production') {
      logger.info('Retrying database connection in 5 seconds...');
      setTimeout(connectDB, 5000);
    } else {
      process.exit(1);
    }
  }
};

// ==================== GRACEFUL SHUTDOWN ====================

const gracefulShutdown = async (signal) => {
  logger.info(`${signal} received. Starting graceful shutdown...`);
  
  const shutdownTimeout = setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30000); // 30 seconds timeout

  try {
    // Close HTTP server
    if (server) {
      await new Promise((resolve) => {
        server.close(() => {
          logger.info('✅ HTTP server closed');
          resolve();
        });
      });
    }

    // Close database connection
    if (mongoose.connection.readyState === 1) {
      await mongoose.connection.close(false);
      logger.info('✅ MongoDB connection closed');
    }

    clearTimeout(shutdownTimeout);
    logger.info('✅ Graceful shutdown completed');
    process.exit(0);
    
  } catch (error) {
    logger.error('Error during graceful shutdown', error);
    clearTimeout(shutdownTimeout);
    process.exit(1);
  }
};

// ==================== PERFORMANCE MONITORING ====================

const startPerformanceMonitoring = () => {
  if (process.env.NODE_ENV === 'production') {
    // Monitor memory usage
    setInterval(() => {
      const memoryUsage = process.memoryUsage();
      const memoryMB = {
        rss: Math.round(memoryUsage.rss / 1024 / 1024),
        heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024),
        heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024),
        external: Math.round(memoryUsage.external / 1024 / 1024)
      };
      
      if (memoryMB.heapUsed > 500) { // Alert if using > 500MB
        logger.warn('High memory usage detected', { memory: memoryMB });
      }
    }, 60000); // Check every minute
    
    // Monitor event loop lag
    let lastCheck = Date.now();
    setInterval(() => {
      const now = Date.now();
      const lag = now - lastCheck - 1000; // Should be close to 1000ms
      lastCheck = now;
      
      if (lag > 100) { // Alert if lag > 100ms
        logger.warn('Event loop lag detected', { lag: `${lag}ms` });
      }
    }, 1000);
  }
};

// ==================== SECURITY HEADERS MIDDLEWARE ====================

app.use((req, res, next) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Remove X-Powered-By
  res.removeHeader('X-Powered-By');
  
  // Rate limiting headers (if using rate limiter)
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  
  next();
});

// ==================== REQUEST LOGGING MIDDLEWARE ====================

app.use((req, res, next) => {
  const startTime = Date.now();
  
  // Log request
  logger.info('Incoming request', {
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('user-agent')
  });
  
  // Capture response finish
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const logLevel = res.statusCode >= 400 ? 'warn' : 'info';
    
    logger[logLevel]('Request completed', {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      contentLength: res.get('Content-Length') || 0
    });
  });
  
  next();
});

// ==================== HEALTH CHECK ENDPOINT ====================

app.get('/health', (req, res) => {
  const health = {
    status: 'UP',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    environment: process.env.NODE_ENV
  };
  
  const status = health.database === 'connected' ? 200 : 503;
  res.status(status).json(health);
});

// ==================== START SERVER ====================

let server;

const startServer = async () => {
  try {
    // Connect to database
    await connectDB();
    
    // Start performance monitoring
    startPerformanceMonitoring();
    
    const PORT = process.env.PORT || 3000;
    const HOST = process.env.HOST || '0.0.0.0';
    
    server = app.listen(PORT, HOST, () => {
      logger.info('🚀 Server started successfully', {
        port: PORT,
        host: HOST,
        environment: process.env.NODE_ENV,
        nodeVersion: process.version,
        pid: process.pid,
        uptime: process.uptime()
      });
      
      console.log(`
===========================================
       🚀 EXPRESS API SERVER
===========================================
✅ Status:    Running
📡 Port:      ${PORT}
🌍 Host:      ${HOST}
📁 Env:       ${process.env.NODE_ENV}
⏰ Started:   ${new Date().toLocaleString()}
🔗 Health:    http://${HOST}:${PORT}/health
===========================================
      `);
    });
    
    // Handle server errors
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        logger.error(`Port ${PORT} is already in use`, error);
        process.exit(1);
      } else {
        logger.error('Server error', error);
      }
    });
    
    // Setup graceful shutdown handlers
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
    // Handle unhandled rejections
    process.on('unhandledRejection', (error) => {
      logger.error('Unhandled Promise Rejection', error);
      
      // In production, don't crash immediately
      if (process.env.NODE_ENV === 'production') {
        // Optionally send to monitoring service
      } else {
        // In development, exit to see the error
        process.exit(1);
      }
    });
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception', error);
      
      // Give time for logging before exit
      setTimeout(() => {
        process.exit(1);
      }, 1000);
    });
    
  } catch (error) {
    logger.error('Failed to start server', error);
    process.exit(1);
  }
};

// Start the application
startServer();

// Export for testing
module.exports = { app, server, connectDB };