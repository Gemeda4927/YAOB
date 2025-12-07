const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { setupSwagger } = require('./config/swagger');
const authRoutes = require('./routes/auth.routes');

const app = express();


app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Log every request
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// -------------------- SWAGGER --------------------
if (process.env.NODE_ENV !== 'production') {
  setupSwagger(app, '/docs');
}

// -------------------- ROOT ROUTE --------------------
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Welcome to Express API Server',
    version: 'v1.0.0',
    status: 'running'
  });
});

// -------------------- ROUTES --------------------
app.use('/api/v1/auth', authRoutes);

// -------------------- 404 HANDLER --------------------
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: `Cannot ${req.method} ${req.url}`
    }
  });
});

// -------------------- GLOBAL ERROR HANDLER --------------------
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(err.statusCode || 500).json({
    success: false,
    error: {
      code: err.code || 'INTERNAL_ERROR',
      message: err.message || 'Internal Server Error'
    }
  });
});

module.exports = app;
