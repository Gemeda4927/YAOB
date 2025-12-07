const express = require('express');
const cors = require('cors');

const app = express();

// MIDDLEWARE
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ROUTES
const authRoutes = require('./routes/auth.routes');

// ROOT ROUTE
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to Express API Server',
    version: 'v1',
    timestamp: new Date().toISOString(),
    status: 'running'
  });
});

// API VERSIONING
app.use('/api/v1/auth', authRoutes);

// 404 HANDLER
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

module.exports = app;
