const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const compression = require('compression')
const rateLimit = require('express-rate-limit')
const mongoSanitize = require('express-mongo-sanitize')
const xss = require('xss-clean')
const hpp = require('hpp')
const morgan = require('morgan')

const authRoutes = require('./routes/auth.routes')

const app = express()

/* ===================== SECURITY ===================== */
app.use(helmet())

app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? process.env.ALLOWED_ORIGINS?.split(',') || []
    : '*',
  credentials: true
}))

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 100 : 1000,
  standardHeaders: true,
  legacyHeaders: false
})

app.use(express.json({ limit: '10kb' }))
app.use(express.urlencoded({ extended: true, limit: '10kb' }))

app.use(mongoSanitize())
app.use(xss())
app.use(hpp())
app.use(compression())

/* ===================== LOGGING ===================== */
app.use(
  process.env.NODE_ENV === 'development'
    ? morgan('dev')
    : morgan('combined')
)

/* ===================== ROOT ===================== */
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Express API Server',
    status: 'running',
    apiBase: '/api/v1'
  })
})

/* ===================== HEALTH ===================== */
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'UP',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  })
})

/* ===================== API v1 ===================== */
app.use('/api/v1', apiLimiter)

app.get('/api/v1', (req, res) => {
  res.json({
    success: true,
    version: 'v1',
    endpoints: {
      auth: {
        signup: 'POST /api/v1/auth/signup',
        login: 'POST /api/v1/auth/login',
        me: 'GET /api/v1/auth/me',
        updateProfile: 'PATCH /api/v1/auth/update-profile',
        changePassword: 'PATCH /api/v1/auth/change-password',
        forgotPassword: 'POST /api/v1/auth/forgot-password',
        resetPassword: 'PATCH /api/v1/auth/reset-password/:token',
        logout: 'POST /api/v1/auth/logout'
      }
    }
  })
})

app.use('/api/v1/auth', authRoutes)

/* ===================== 404 API ===================== */
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'ENDPOINT_NOT_FOUND',
      message: `Cannot ${req.method} ${req.originalUrl}`
    }
  })
})

/* ===================== 404 GLOBAL ===================== */
app.all('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: `Cannot ${req.method} ${req.originalUrl}`
    }
  })
})

/* ===================== ERROR HANDLER ===================== */
app.use((err, req, res, next) => {
  console.error(err)

  res.status(err.statusCode || 500).json({
    success: false,
    error: {
      message:
        process.env.NODE_ENV === 'production'
          ? 'Something went wrong'
          : err.message
    }
  })
})

module.exports = app