const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const packageJson = require('../package.json');

/**
 * Swagger/OpenAPI 3.0 Configuration for Backend API
 */

// Environment configuration
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = process.env.PORT || 3000;
const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000/api/v1';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const APP_NAME = process.env.APP_NAME || 'Backend API';
const APP_VERSION = process.env.APP_VERSION || packageJson.version || '1.0.0';
const FEATURE_SWAGGER = process.env.FEATURE_SWAGGER !== 'false';

// Configure API servers for different environments
const servers = [];

servers.push(
  {
    url: 'http://localhost:3000/api/v1',
    description: 'Local Development Server',
    variables: {
      port: {
        default: '3000',
        description: 'Port number',
        enum: ['3000', '3001', '3002']
      }
    }
  },
  {
    url: 'http://localhost:3000',
    description: 'Local API Server',
  }
);

servers.push({
  url: API_BASE_URL,
  description: 'Configured API Server'
});

servers.push(
  {
    url: 'https://youareok.onrender.com/api/v1',
    description: 'Render Production Server',
  },
  {
    url: 'https://youareok.onrender.com',
    description: 'Render Production API Server',
  }
);

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: APP_NAME,
      version: APP_VERSION,
      description: `
# ${APP_NAME} - Comprehensive API Documentation

## API Overview
This RESTful API provides a complete user management and authentication system with JWT-based security,
profile management, and administrative functions.

## Security Implementation
- JWT Bearer Authentication: All protected endpoints require a valid JWT token
- Token Refresh Mechanism: Secure token renewal without re-authentication
- Role-Based Access Control: User, admin, and super-admin role permissions
- Rate Limiting: Protection against abuse with configurable request limits
- Password Security: Bcrypt hashing with configurable complexity requirements

## Rate Limiting Configuration
The API implements rate limiting with the following default configuration:
- Maximum Requests: ${process.env.API_RATE_LIMIT_MAX || 100} requests
- Time Window: ${Math.round((process.env.API_RATE_LIMIT_WINDOW_MS || 900000) / 60000)} minutes
- Response Headers: Includes rate limit information in response headers

## API Versioning
Current API Version: v${APP_VERSION}
Base Path: /api/v1


## Environment
Current environment: ${NODE_ENV}
      `.trim(),
      termsOfService: 'https://youareok.onrender.com/terms',
      contact: {
        name: 'API Support Team',
        email: process.env.EMAIL_USER || 'gemedatam@gmail.com',
        url: process.env.FRONTEND_URL,
      },
      license: {
        name: 'MIT License',
        url: 'https://opensource.org/licenses/MIT',
      },
      xLogo: {
        url: 'https://youareok.onrender.com/logo.png',
        backgroundColor: '#FFFFFF',
        altText: 'API Logo'
      }
    },
    servers: servers,
    externalDocs: {
      description: 'Frontend Application Documentation',
      url: FRONTEND_URL
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: `JWT Access Token for user authentication. Token expiration: ${process.env.JWT_EXPIRES_IN || '7 days'}`,
        }
      },
      schemas: {
        User: {
          type: 'object',
          required: ['_id', 'name', 'email'],
          properties: {
            _id: { 
              type: 'string', 
              example: '507f1f77bcf86cd799439011',
              description: 'MongoDB ObjectId identifier'
            },
            name: { 
              type: 'string', 
              example: 'John Doe',
              minLength: 2,
              maxLength: 50,
              description: 'User full name'
            },
            email: { 
              type: 'string', 
              format: 'email', 
              example: 'john@example.com',
              description: 'Valid email address for user account'
            },
            role: { 
              type: 'string', 
              enum: ['user', 'admin', 'super-admin'], 
              example: 'user',
              default: 'user',
              description: 'User role for access control'
            },
            isActive: {
              type: 'boolean',
              example: true,
              description: 'Account activation status'
            },
            isEmailVerified: {
              type: 'boolean',
              example: false,
              description: 'Email verification status'
            },
            loginAttempts: {
              type: 'number',
              example: 0,
              description: 'Count of failed login attempts'
            },
            lockUntil: {
              type: 'string',
              format: 'date-time',
              description: 'Timestamp when account lock expires'
            },
            lastLogin: {
              type: 'string',
              format: 'date-time',
              description: 'Timestamp of last successful login'
            },
            createdAt: { 
              type: 'string', 
              format: 'date-time',
              example: '2025-12-07T18:05:49.123Z',
              description: 'Account creation timestamp'
            },
            updatedAt: { 
              type: 'string', 
              format: 'date-time',
              example: '2025-12-07T18:05:49.123Z',
              description: 'Account last update timestamp'
            },
          },
        },
        LoginRequest: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { 
              type: 'string', 
              format: 'email', 
              example: 'user@example.com',
              description: 'Registered email address for authentication'
            },
            password: { 
              type: 'string', 
              format: 'password', 
              example: 'Password123!',
              description: 'User password for authentication',
              minLength: 6
            },
          },
        },
        LoginResponse: {
          type: 'object',
          properties: {
            success: {
              type: 'boolean',
              example: true,
              description: 'Authentication success status'
            },
            data: {
              type: 'object',
              properties: {
                user: {
                  $ref: '#/components/schemas/User',
                  description: 'Authenticated user information'
                },
                tokens: {
                  type: 'object',
                  description: 'Authentication tokens',
                  properties: {
                    accessToken: {
                      type: 'string',
                      description: 'JWT Access Token for API authorization',
                      example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                    },
                    refreshToken: {
                      type: 'string',
                      description: 'JWT Refresh Token for token renewal',
                      example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                    },
                    expiresIn: {
                      type: 'string',
                      example: '7d',
                      description: 'Access token expiration period'
                    }
                  }
                }
              }
            },
            message: {
              type: 'string',
              example: 'Login successful',
              description: 'Authentication result message'
            }
          }
        },
        RegisterRequest: {
          type: 'object',
          required: ['name', 'email', 'password'],
          properties: {
            name: { 
              type: 'string', 
              example: 'John Doe',
              minLength: 2,
              maxLength: 50,
              description: 'Full name for user registration'
            },
            email: { 
              type: 'string', 
              format: 'email', 
              example: 'user@example.com',
              description: 'Email address for account creation'
            },
            password: { 
              type: 'string', 
              format: 'password', 
              example: 'Password123!',
              minLength: 6,
              description: 'Account password with minimum 6 characters'
            },
            role: { 
              type: 'string', 
              enum: ['user', 'admin'], 
              example: 'user',
              default: 'user',
              description: 'Optional role assignment during registration'
            },
          },
        },
        RefreshTokenRequest: {
          type: 'object',
          required: ['refreshToken'],
          properties: {
            refreshToken: {
              type: 'string',
              example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
              description: 'Valid refresh token for obtaining new access token'
            }
          }
        },
        ForgotPasswordRequest: {
          type: 'object',
          required: ['email'],
          properties: {
            email: {
              type: 'string',
              format: 'email',
              example: 'user@example.com',
              description: 'Email address for password reset initiation'
            }
          }
        },
        ResetPasswordRequest: {
          type: 'object',
          required: ['token', 'password'],
          properties: {
            token: {
              type: 'string',
              description: 'Password reset token received via email',
              example: 'abc123def456'
            },
            password: {
              type: 'string',
              format: 'password',
              example: 'NewPassword123!',
              minLength: 6,
              description: 'New password for account'
            }
          }
        },
        EmailVerificationRequest: {
          type: 'object',
          required: ['token'],
          properties: {
            token: {
              type: 'string',
              description: 'Email verification token',
              example: 'verification_token_123'
            }
          }
        },
        HealthCheckResponse: {
          type: 'object',
          properties: {
            status: {
              type: 'string',
              enum: ['healthy', 'degraded', 'unhealthy'],
              example: 'healthy',
              description: 'Overall system health status'
            },
            timestamp: {
              type: 'string',
              format: 'date-time',
              description: 'Health check execution timestamp'
            },
            uptime: {
              type: 'number',
              description: 'System uptime in seconds'
            },
            services: {
              type: 'object',
              properties: {
                database: {
                  type: 'object',
                  properties: {
                    status: {
                      type: 'string',
                      enum: ['connected', 'disconnected', 'error']
                    },
                    responseTime: {
                      type: 'number',
                      description: 'Database response time in milliseconds'
                    }
                  }
                },
                memory: {
                  type: 'object',
                  properties: {
                    usage: {
                      type: 'number',
                      description: 'Memory usage percentage'
                    },
                    free: {
                      type: 'number',
                      description: 'Free memory in megabytes'
                    }
                  }
                }
              }
            }
          }
        },
        EmailStatusResponse: {
          type: 'object',
          properties: {
            success: {
              type: 'boolean',
              description: 'Email operation status'
            },
            messageId: {
              type: 'string',
              description: 'Email message identifier'
            },
            recipient: {
              type: 'string',
              format: 'email',
              description: 'Email recipient address'
            },
            timestamp: {
              type: 'string',
              format: 'date-time',
              description: 'Email send timestamp'
            }
          }
        },
        ErrorResponse: {
          type: 'object',
          required: ['success', 'error'],
          properties: {
            success: { 
              type: 'boolean', 
              example: false,
              description: 'Operation success status'
            },
            error: {
              type: 'object',
              required: ['code', 'message'],
              properties: {
                code: { 
                  type: 'string', 
                  example: 'VALIDATION_ERROR',
                  enum: [
                    'VALIDATION_ERROR',
                    'UNAUTHORIZED',
                    'FORBIDDEN',
                    'NOT_FOUND',
                    'CONFLICT',
                    'TOO_MANY_REQUESTS',
                    'INTERNAL_SERVER_ERROR',
                    'EMAIL_SEND_ERROR',
                    'SERVICE_UNAVAILABLE'
                  ],
                  description: 'Error category code'
                },
                message: { 
                  type: 'string', 
                  example: 'Invalid input data',
                  description: 'Human-readable error message'
                },
                details: { 
                  type: 'array',
                  items: { type: 'string' },
                  example: ['Email must be valid', 'Password must be at least 6 characters'],
                  description: 'Detailed error information'
                },
              },
            },
            timestamp: { 
              type: 'string', 
              format: 'date-time',
              example: '2025-12-07T18:05:49.123Z',
              description: 'Error occurrence timestamp'
            },
          },
        },
        SuccessResponse: {
          type: 'object',
          required: ['success'],
          properties: {
            success: { 
              type: 'boolean', 
              example: true,
              description: 'Operation success status'
            },
            data: {
              type: 'object',
              description: 'Response data payload'
            },
            message: {
              type: 'string',
              example: 'Operation completed successfully',
              description: 'Success message'
            },
            timestamp: { 
              type: 'string', 
              format: 'date-time',
              example: '2025-12-07T18:05:49.123Z',
              description: 'Response timestamp'
            },
          },
        },
        Pagination: {
          type: 'object',
          properties: {
            page: {
              type: 'integer',
              example: 1,
              minimum: 1,
              description: 'Current page number'
            },
            limit: {
              type: 'integer',
              example: parseInt(process.env.PAGINATION_LIMIT) || 50,
              maximum: parseInt(process.env.PAGINATION_LIMIT) || 50,
              description: 'Items per page'
            },
            totalPages: {
              type: 'integer',
              example: 5,
              description: 'Total number of pages'
            },
            totalItems: {
              type: 'integer',
              example: 123,
              description: 'Total number of items'
            },
            hasNext: {
              type: 'boolean',
              example: true,
              description: 'Next page availability'
            },
            hasPrev: {
              type: 'boolean',
              example: false,
              description: 'Previous page availability'
            }
          }
        }
      },
      responses: {
        Unauthorized: {
          description: 'Authentication token is missing, invalid, or expired',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/ErrorResponse'
              },
              example: {
                success: false,
                error: {
                  code: 'UNAUTHORIZED',
                  message: 'Authentication token is missing or invalid'
                },
                timestamp: '2025-12-07T18:05:49.123Z'
              }
            }
          }
        },
        Forbidden: {
          description: 'User does not have required permissions for the requested operation',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/ErrorResponse'
              },
              example: {
                success: false,
                error: {
                  code: 'FORBIDDEN',
                  message: 'Insufficient permissions to access this resource'
                },
                timestamp: '2025-12-07T18:05:49.123Z'
              }
            }
          }
        },
        NotFound: {
          description: 'Requested resource not found in the system',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/ErrorResponse'
              },
              example: {
                success: false,
                error: {
                  code: 'NOT_FOUND',
                  message: 'User not found'
                },
                timestamp: '2025-12-07T18:05:49.123Z'
              }
            }
          }
        },
        ValidationError: {
          description: 'Request validation failed due to invalid input data',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/ErrorResponse'
              },
              example: {
                success: false,
                error: {
                  code: 'VALIDATION_ERROR',
                  message: 'Invalid input data',
                  details: ['Email must be valid', 'Password must be at least 6 characters']
                },
                timestamp: '2025-12-07T18:05:49.123Z'
              }
            }
          }
        },
        TooManyRequests: {
          description: `Rate limit exceeded for API requests`,
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/ErrorResponse'
              },
              example: {
                success: false,
                error: {
                  code: 'TOO_MANY_REQUESTS',
                  message: 'Rate limit exceeded. Please try again later.'
                },
                timestamp: '2025-12-07T18:05:49.123Z'
              }
            }
          }
        },
        InternalServerError: {
          description: 'Internal server error occurred during request processing',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/ErrorResponse'
              },
              example: {
                success: false,
                error: {
                  code: 'INTERNAL_SERVER_ERROR',
                  message: 'An unexpected error occurred'
                },
                timestamp: '2025-12-07T18:05:49.123Z'
              }
            }
          }
        },
        ServiceUnavailable: {
          description: 'Required service is temporarily unavailable',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/ErrorResponse'
              },
              example: {
                success: false,
                error: {
                  code: 'SERVICE_UNAVAILABLE',
                  message: 'Email service is currently unavailable'
                },
                timestamp: '2025-12-07T18:05:49.123Z'
              }
            }
          }
        },
        EmailSendError: {
          description: 'Failed to send email due to configuration or network issues',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/ErrorResponse'
              },
              example: {
                success: false,
                error: {
                  code: 'EMAIL_SEND_ERROR',
                  message: 'Failed to send verification email',
                  details: ['SMTP connection failed', 'Invalid recipient address']
                },
                timestamp: '2025-12-07T18:05:49.123Z'
              }
            }
          }
        }
      },
      parameters: {
        userIdParam: {
          name: 'id',
          in: 'path',
          required: true,
          schema: {
            type: 'string',
            pattern: '^[0-9a-fA-F]{24}$'
          },
          description: 'User ID (MongoDB ObjectId format)'
        },
        pageParam: {
          name: 'page',
          in: 'query',
          schema: {
            type: 'integer',
            default: 1,
            minimum: 1
          },
          description: 'Page number for paginated results'
        },
        limitParam: {
          name: 'limit',
          in: 'query',
          schema: {
            type: 'integer',
            default: parseInt(process.env.PAGINATION_LIMIT) || 50,
            minimum: 1,
            maximum: 100
          },
          description: 'Number of items per page for pagination'
        },
        sortParam: {
          name: 'sort',
          in: 'query',
          schema: {
            type: 'string',
            enum: ['asc', 'desc', 'createdAt', '-createdAt', 'name', '-name', 'email', '-email'],
            default: 'createdAt'
          },
          description: 'Sort order for results'
        },
        searchParam: {
          name: 'search',
          in: 'query',
          schema: {
            type: 'string'
          },
          description: 'Search query for filtering results'
        },
        statusParam: {
          name: 'status',
          in: 'query',
          schema: {
            type: 'string',
            enum: ['active', 'inactive', 'pending', 'suspended']
          },
          description: 'Filter by user status'
        },
        emailTypeParam: {
          name: 'type',
          in: 'query',
          schema: {
            type: 'string',
            enum: ['verification', 'password-reset', 'notification', 'welcome']
          },
          description: 'Email template type for sending'
        }
      }
    },
    security: [{
      bearerAuth: []
    }],
    tags: [
      {
        name: 'Authentication',
        description: 'User authentication, registration, and token management operations',
      },
      {
        name: 'Users',
        description: 'User account management and administration',
      },
      {
        name: 'Profile',
        description: 'User profile management and personal information',
      },
      {
        name: 'Admin',
        description: 'Administrative operations requiring elevated privileges',
      }
    ],
    xTagGroups: [
      {
        name: 'User Management',
        tags: ['Authentication', 'Users', 'Profile']
      },
      {
        name: 'Administration',
        tags: ['Admin']
      },
      {
        name: 'System Services',
        tags: ['Health', 'Email']
      }
    ]
  },
  apis: [
    './routes/*.js',
    './controllers/*.js',
    './models/*.js',
    './docs/*.yml',
    './docs/*.yaml',
    './middleware/*.js'
  ],
};

const swaggerSpec = swaggerJsDoc(swaggerOptions);

const swaggerUIOptions = {
  explorer: true,
  customCss: `
    .swagger-ui .topbar { display: none }
    .swagger-ui .info .title { 
      color: #3b4151;
      font-size: 2.5rem;
      margin-bottom: 15px;
    }
    .swagger-ui .info .description { 
      font-size: 14px;
      line-height: 1.6;
    }
    .swagger-ui .info .description h2 {
      margin-top: 20px;
      margin-bottom: 10px;
      color: #3b4151;
    }
    .swagger-ui .info .description h3 {
      margin-top: 15px;
      margin-bottom: 8px;
      color: #3b4151;
    }
    .swagger-ui .scheme-container { 
      background: #f8f9fa;
      border-radius: 4px;
      padding: 15px;
      margin: 20px 0;
      border-left: 4px solid #4CAF50;
    }
    .swagger-ui .btn.authorize { 
      background-color: #4CAF50;
      border-color: #4CAF50;
    }
    .swagger-ui .opblock-tag { 
      font-size: 18px;
      font-weight: 600;
      padding: 10px 0;
      border-bottom: 2px solid #e8e8e8;
    }
    .swagger-ui .opblock-tag-section { 
      margin-bottom: 30px;
    }
    .swagger-ui .opblock { 
      border-radius: 4px;
      margin-bottom: 15px;
      border: 1px solid #e8e8e8;
    }
    .swagger-ui .model { 
      font-size: 12px;
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    }
    .swagger-ui .parameters-col_name { 
      font-weight: 600;
      color: #333;
    }
    .swagger-ui .opblock-summary-path {
      font-weight: 600;
    }
    .swagger-ui .response-col_description {
      font-size: 13px;
    }
  `,
  customSiteTitle: `${APP_NAME} Documentation - Version ${APP_VERSION}`,
  customfavIcon: '/favicon.ico',
  swaggerOptions: {
    persistAuthorization: true,
    docExpansion: 'list',
    filter: true,
    displayRequestDuration: true,
    defaultModelsExpandDepth: 2,
    defaultModelExpandDepth: 2,
    tryItOutEnabled: true,
    displayOperationId: true,
    showExtensions: true,
    showCommonExtensions: true,
    syntaxHighlight: {
      activate: true,
      theme: 'tomorrow-night'
    },
    operationsSorter: 'alpha',
    tagsSorter: 'alpha',
    validatorUrl: 'https://validator.swagger.io/validator',
    requestSnippetsEnabled: true,
    requestSnippets: {
      generators: {
        curl_bash: {
          title: "cURL (bash)",
          syntax: "bash"
        },
        curl_powershell: {
          title: "cURL (PowerShell)",
          syntax: "powershell"
        },
        curl_cmd: {
          title: "cURL (CMD)",
          syntax: "bash"
        }
      }
    }
  },
};

const setupSwagger = (app, path = '/docs') => {
  if (!FEATURE_SWAGGER) {
    console.log('Swagger documentation is disabled (FEATURE_SWAGGER=false)');
    return;
  }

  try {
    app.use(path, swaggerUi.serve, swaggerUi.setup(swaggerSpec, swaggerUIOptions));
    
    app.get(`${path}.json`, (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.json(swaggerSpec);
    });
    
    app.get(`${path}.yaml`, (req, res) => {
      res.setHeader('Content-Type', 'text/yaml');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.json(swaggerSpec);
    });
    
    app.get(`${path}/health`, (req, res) => {
      res.json({
        status: 'healthy',
        service: 'swagger-documentation',
        version: APP_VERSION,
        environment: NODE_ENV,
        timestamp: new Date().toISOString(),
        endpoints: {
          ui: `${req.protocol}://${req.get('host')}${path}`,
          json: `${req.protocol}://${req.get('host')}${path}.json`,
          yaml: `${req.protocol}://${req.get('host')}${path}.yaml`
        }
      });
    });

    console.log('\n' + '='.repeat(70));
    console.log('API DOCUMENTATION SERVICE INITIALIZATION');
    console.log('='.repeat(70));
    console.log(`Service Name:    ${APP_NAME}`);
    console.log(`API Version:     ${APP_VERSION}`);
    console.log(`Environment:     ${NODE_ENV}`);
    console.log(`Server Port:     ${PORT}`);
    console.log('-' .repeat(70));
    console.log('Documentation Endpoints:');
    console.log(`Swagger UI:      http://localhost:${PORT}${path}`);
    console.log(`OpenAPI JSON:    http://localhost:${PORT}${path}.json`);
    console.log(`OpenAPI YAML:    http://localhost:${PORT}${path}.yaml`);
    console.log(`Health Check:    http://localhost:${PORT}${path}/health`);
    console.log('='.repeat(70));
    
    if (NODE_ENV === 'production') {
      console.log('Production Environment URLs:');
      console.log(`Swagger UI:      https://youareok.onrender.com${path}`);
      console.log(`API Base URL:    ${API_BASE_URL}`);
      console.log(`Frontend URL:    ${FRONTEND_URL}`);
      console.log('='.repeat(70));
    }
    
    console.log('Documentation Tags Available:');
    console.log('- Authentication: User authentication and token management');
    console.log('- Users:         User account administration');
    console.log('- Profile:       User profile management');
    console.log('- Admin:         Administrative operations');
    console.log('- Health:        System health monitoring and metrics');
    console.log('- Email:         Email service operations and templates');
    console.log('='.repeat(70));
    
  } catch (error) {
    console.error('Failed to initialize Swagger documentation:', error.message);
    console.error('Error Stack:', error.stack);
    console.error('Continuing application startup without Swagger UI');
  }
};

module.exports = { 
  setupSwagger, 
  swaggerSpec,
  swaggerUIOptions 
};