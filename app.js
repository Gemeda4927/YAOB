const express = require('express');
const cors = require('cors');
const { setupSwagger } = require('./config/swagger');
const authRoutes = require('./routes/auth.routes');

const app = express();

// -------------------- MIDDLEWARE --------------------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// -------------------- SWAGGER --------------------
setupSwagger(app, '/docs');

// -------------------- ROOT ROUTE --------------------
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to Express API Server',
    version: 'v1',
    timestamp: new Date().toISOString(),
    status: 'running',
    availableRoutes: [
      '/docs',
      '/api/v1/auth/signup',
      '/api/v1/auth/login',
      '/api/v1/auth/forgot-password'
    ]
  });
});

// -------------------- API VERSIONING --------------------
app.use('/api/v1/auth', authRoutes);

// -------------------- 404 HANDLER --------------------
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
  });
});

module.exports = app;