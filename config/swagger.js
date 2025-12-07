// config/swagger.js
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const packageJson = require('../package.json');

/**
 * Swagger/OpenAPI 3.0 Configuration
 */

// Swagger Options
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Backend API Documentation',
      version: packageJson.version || '1.0.0',
      description: 'API Documentation for Authentication System',
      contact: {
        name: 'API Support',
        email: 'gemedatam@gmail.com',
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT',
      },
    },
    servers: [
      {
        url: 'http://localhost:3000',
        description: 'Development Server',
      },
      {
        url: 'http://localhost:3000/api/v1',
        description: 'API v1 Server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'JWT Authorization header',
        },
      },
      schemas: {
        SuccessResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            data: { type: 'object' },
            message: { type: 'string' },
            timestamp: { type: 'string', format: 'date-time' },
          },
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string' },
                message: { type: 'string' },
              },
            },
            timestamp: { type: 'string', format: 'date-time' },
          },
        },
        User: {
          type: 'object',
          properties: {
            _id: { type: 'string' },
            name: { type: 'string' },
            email: { type: 'string', format: 'email' },
            role: { type: 'string', enum: ['user', 'admin', 'super-admin'] },
          },
        },
      },
    },
    tags: [
      {
        name: 'Authentication',
        description: 'User authentication and authorization',
      },
    ],
  },
  apis: ['./routes/*.js'],
};

const swaggerSpec = swaggerJsDoc(swaggerOptions);

/**
 * Setup Swagger middleware
 * @param {Express.Application} app - Express app instance
 * @param {string} path - Path for Swagger UI (default: '/api-docs')
 */
const setupSwagger = (app, path = '/api-docs') => {
  app.use(path, swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  
  // Serve Swagger JSON
  app.get(`${path}.json`, (req, res) => {
    res.json(swaggerSpec);
  });
  
  console.log(`📚 Swagger UI available at: http://localhost:3000${path}`);
};

module.exports = { setupSwagger };