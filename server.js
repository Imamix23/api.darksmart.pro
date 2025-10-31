const express = require('express');
const path = require('path');
const helmet = require('helmet');
const morgan = require('morgan');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Trust proxy for deployment behind Nginx
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS configuration
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://api.darksmart.pro'],
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Logging
app.use(morgan('combined'));

// Body parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: require('./package.json').version || '1.0.0'
  });
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));

// API Routes
const authRouter = require('./routes/auth');
const oauthRouter = require('./routes/oauth');
const devicesRouter = require('./routes/devices');
const automationsRouter = require('./routes/automations');
const smarthomeRouter = require('./smarthome');

app.use('/auth', authRouter);
app.use('/oauth', oauthRouter);
app.use('/api/devices', devicesRouter);
app.use('/api/automations', automationsRouter);
app.use('/smarthome', smarthomeRouter);

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d',
  etag: true
}));

// SPA fallback - serve index.html for client-side routing
app.get('*', (req, res, next) => {
  // Skip API routes
  if (req.path.startsWith('/api/') || 
      req.path.startsWith('/auth/') || 
      req.path.startsWith('/oauth/') ||
      req.path.startsWith('/smarthome/')) {
    return next();
  }
  
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[Error]', err);
  
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal server error';
  
  res.status(statusCode).json({
    error: {
      message,
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    }
  });
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
const PORT = process.env.PORT || 5050;
app.listen(PORT, () => {
  console.log(`🚀 DarkSmart API server running on port ${PORT}`);
  console.log(`📡 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 HTTPS: ${process.env.NODE_ENV === 'production' ? 'Enabled (via Nginx)' : 'Disabled (dev mode)'}`);
});

module.exports = app;