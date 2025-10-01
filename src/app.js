/* eslint-disable no-undef */

const express = require('express');
const logger = require('morgan');
const passport = require('./passport/passportConfig');
const cors = require('cors');
const path = require('path');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./docs/swagger.json');
require('dotenv').config();

const authRouter = require('./routes/api/authRoutes');
const corsOptions = require('./cors');

// --- Checks for required environment variables ---
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT secret is missing.');

const nodemailerApiKey = process.env.GMAIL_APP_PASSWORD;
if (!nodemailerApiKey) throw new Error('Nodemailer API key is missing.');

const app = express();
const formatsLogger = app.get('env') === 'development' ? 'dev' : 'short';

// --- Middleware ---
app.use(logger(formatsLogger));
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Initialize Passport (must be before routes) ---
app.use(passport.initialize());

// --- Swagger API Docs ---
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// --- Routes ---
app.use('/api', authRouter); // includes /users, OAuth, etc.

// --- 404 handler ---
app.use((_, res) => {
  res.status(404).json({
    status: 'error',
    code: 404,
    message: 'Use API on routes: /api/users, /api/private or /api/public',
    data: 'Not found',
  });
});

// --- Passport unauthorized errors (JWT) ---
app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ message: 'Invalid token' });
  }
  next(err);
});

// --- General 500 error handler ---
app.use((err, _, res) => {
  console.error(err.stack);
  res.status(500).json({
    status: 'fail',
    code: 500,
    message: err.message,
    data: 'Internal Server Error',
  });
});

module.exports = app;
