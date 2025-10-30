const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Import and mount smart home router
const smarthomeRouter = require('./smarthome');
app.use('/smarthome', smarthomeRouter);
const authRouter = require('./auth');
app.use('/auth', authRouter);

// ========================================
// CONFIGURATION
// ========================================
const CONFIG = {
  JWT_SECRET: process.env.JWT_SECRET || 'JWT_SECRET=a7f3d9e2c8b4f1a6e9d2c5b8f4a1e7d3c9b6f2a8e5d1c7b4f9a2e6d3c8b5f1a9e4d2c7b6f3a8e5d1c9b4f7a2e6d3c8b5f1a9e4d2c7b6f3a8e5d1',
  TOKEN_EXPIRY: 3600, // 1 hour in seconds
  REFRESH_TOKEN_EXPIRY: 30 * 24 * 60 * 60, // 30 days in seconds
  OAUTH_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || '1035771497728-c7d2klrleg3dq8vkgqubosvrbr6ourgl.apps.googleusercontent.com',
  OAUTH_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || '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',
  BASE_URL: 'https://api.darksmart.pro'
};

// ========================================
// IN-MEMORY STORAGE (Replace with Database)
// ========================================
const storage = {
  users: new Map(), // userId -> { email, password, profile }
  authCodes: new Map(), // code -> { userId, clientId, redirectUri, scope, expiresAt }
  accessTokens: new Map(), // token -> { userId, clientId, scope, expiresAt }
  refreshTokens: new Map() // token -> { userId, clientId, scope }
};

// Demo user for testing
const demoUserId = 'user_' + crypto.randomBytes(8).toString('hex');
storage.users.set(demoUserId, {
  email: 'demo@darksmart.pro',
  password: bcrypt.hashSync('demo123', 10),
  profile: {
    name: 'Demo User',
    agentUserId: demoUserId // This is correct
  }
});

// ========================================
// HELPER FUNCTIONS
// ========================================

// Generate secure random token
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('base64url');
}

// Verify client credentials
function verifyClient(clientId, clientSecret = null) {
  if (clientId !== CONFIG.OAUTH_CLIENT_ID) {
    return false;
  }
  if (clientSecret && clientSecret !== CONFIG.OAUTH_CLIENT_SECRET) {
    return false;
  }
  return true;
}

// Create JWT access token
function createAccessToken(userId, clientId, scope) {
  const payload = {
    sub: userId,
    client_id: clientId,
    scope: scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + CONFIG.TOKEN_EXPIRY
  };
  return jwt.sign(payload, CONFIG.JWT_SECRET);
}

// Verify JWT access token
function verifyAccessToken(token) {
  try {
    return jwt.verify(token, CONFIG.JWT_SECRET);
  } catch (err) {
    return null;
  }
}

// Authenticate user (simplified - expand for your user system)
function authenticateUser(email, password) {
  for (const [userId, user] of storage.users.entries()) {
    if (user.email === email && bcrypt.compareSync(password, user.password)) {
      return userId;
    }
  }
  return null;
}

// ========================================
// OAUTH2 ENDPOINTS
// ========================================

/**
 * Authorization Endpoint (RFC 6749 Section 3.1)
 * GET /oauth/authorize
 * 
 * Query params from Google:
 * - client_id: OAuth client ID
 * - redirect_uri: Where to send the auth code
 * - state: CSRF protection token
 * - response_type: Must be "code"
 * - scope: Requested scopes (e.g., "openid email profile")
 */
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, state, response_type, scope } = req.query;

  // Validate request
  if (!client_id || !redirect_uri || !state || response_type !== 'code') {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing or invalid required parameters'
    });
  }

  if (!verifyClient(client_id)) {
    return res.status(401).json({
      error: 'unauthorized_client',
      error_description: 'Invalid client_id'
    });
  }

  // Store OAuth parameters in session/cookie for POST handler
  // In production, use secure session management
  const sessionId = generateToken(16);
  storage.authCodes.set(`session_${sessionId}`, {
    clientId: client_id,
    redirectUri: redirect_uri,
    state: state,
    scope: scope || 'openid email profile',
    expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
  });

  // Render login form (replace with your UI)
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>DarkSmart Authorization</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          margin: 0;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
          background: white;
          padding: 2rem;
          border-radius: 12px;
          box-shadow: 0 10px 40px rgba(0,0,0,0.1);
          max-width: 400px;
          width: 90%;
        }
        h1 {
          margin: 0 0 0.5rem 0;
          font-size: 1.5rem;
          color: #333;
        }
        .subtitle {
          color: #666;
          font-size: 0.9rem;
          margin-bottom: 1.5rem;
        }
        .scope-list {
          background: #f8f9fa;
          padding: 1rem;
          border-radius: 8px;
          margin-bottom: 1.5rem;
        }
        .scope-item {
          display: flex;
          align-items: center;
          margin: 0.5rem 0;
          font-size: 0.9rem;
          color: #555;
        }
        .scope-item:before {
          content: "✓";
          color: #667eea;
          font-weight: bold;
          margin-right: 0.5rem;
        }
        input {
          width: 100%;
          padding: 0.75rem;
          margin-bottom: 1rem;
          border: 1px solid #ddd;
          border-radius: 6px;
          font-size: 1rem;
          box-sizing: border-box;
        }
        input:focus {
          outline: none;
          border-color: #667eea;
        }
        button {
          width: 100%;
          padding: 0.75rem;
          background: #667eea;
          color: white;
          border: none;
          border-radius: 6px;
          font-size: 1rem;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s;
        }
        button:hover {
          background: #5568d3;
        }
        .demo-info {
          margin-top: 1rem;
          padding: 0.75rem;
          background: #e3f2fd;
          border-radius: 6px;
          font-size: 0.85rem;
          color: #1976d2;
        }
        .error {
          color: #d32f2f;
          font-size: 0.9rem;
          margin-top: 0.5rem;
          display: none;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🏠 Link DarkSmart</h1>
        <p class="subtitle">Google Home wants to access your DarkSmart account</p>
        
        <div class="scope-list">
          <div class="scope-item">Control your smart home devices</div>
          <div class="scope-item">View device status</div>
          <div class="scope-item">Access your profile information</div>
        </div>

        <form id="loginForm" method="POST" action="/oauth/authorize">
          <input type="hidden" name="session_id" value="${sessionId}">
          <input 
            type="email" 
            name="email" 
            placeholder="Email" 
            required 
            autocomplete="email"
            value="demo@darksmart.pro"
          >
          <input 
            type="password" 
            name="password" 
            placeholder="Password" 
            required 
            autocomplete="current-password"
            value="demo123"
          >
          <button type="submit">Authorize</button>
          <div class="error" id="error"></div>
        </form>

        <div class="demo-info">
          <strong>Demo Credentials:</strong><br>
          Email: demo@darksmart.pro<br>
          Password: demo123
        </div>
      </div>

      <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const formData = new FormData(e.target);
          const error = document.getElementById('error');
          
          try {
            const response = await fetch('/oauth/authorize', {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams(formData)
            });
            
            const data = await response.json();
            
            if (data.redirect_uri) {
              window.location.href = data.redirect_uri;
            } else {
              error.textContent = data.error_description || 'Authorization failed';
              error.style.display = 'block';
            }
          } catch (err) {
            error.textContent = 'Network error. Please try again.';
            error.style.display = 'block';
          }
        });
      </script>
    </body>
    </html>
  `);
});

/**
 * Authorization POST Handler
 * POST /oauth/authorize
 * Authenticates user and generates authorization code
 */
app.post('/oauth/authorize', (req, res) => {
  const { session_id, email, password } = req.body;

  // Retrieve session data
  const sessionKey = `session_${session_id}`;
  const sessionData = storage.authCodes.get(sessionKey);

  if (!sessionData || sessionData.expiresAt < Date.now()) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Session expired or invalid'
    });
  }

  // Authenticate user
  const userId = authenticateUser(email, password);
  if (!userId) {
    return res.status(401).json({
      error: 'access_denied',
      error_description: 'Invalid credentials'
    });
  }

  // Generate authorization code
  const authCode = generateToken(32);
  storage.authCodes.set(authCode, {
    userId: userId,
    clientId: sessionData.clientId,
    redirectUri: sessionData.redirectUri,
    scope: sessionData.scope,
    expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
  });

  // Clean up session
  storage.authCodes.delete(sessionKey);

  // Build redirect URI with code and state
  const redirectUrl = new URL(sessionData.redirectUri);
  redirectUrl.searchParams.set('code', authCode);
  redirectUrl.searchParams.set('state', sessionData.state);

  res.json({ redirect_uri: redirectUrl.toString() });
});

/**
 * Token Endpoint (RFC 6749 Section 3.2)
 * POST /oauth/token
 * 
 * Supports two grant types:
 * 1. authorization_code - Exchange auth code for tokens
 * 2. refresh_token - Get new access token using refresh token
 */
app.post('/oauth/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;

  // Verify client credentials
  if (!verifyClient(client_id, client_secret)) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Invalid client credentials'
    });
  }

  // Handle authorization_code grant
  if (grant_type === 'authorization_code') {
    if (!code || !redirect_uri) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing code or redirect_uri'
      });
    }

    const authData = storage.authCodes.get(code);
    if (!authData || authData.expiresAt < Date.now()) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      });
    }

    if (authData.clientId !== client_id || authData.redirectUri !== redirect_uri) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Mismatched client_id or redirect_uri'
      });
    }

    // Generate tokens
    const accessToken = createAccessToken(authData.userId, client_id, authData.scope);
    const newRefreshToken = generateToken(32);

    // Store tokens
    storage.accessTokens.set(accessToken, {
      userId: authData.userId,
      clientId: client_id,
      scope: authData.scope,
      expiresAt: Date.now() + CONFIG.TOKEN_EXPIRY * 1000
    });

    storage.refreshTokens.set(newRefreshToken, {
      userId: authData.userId,
      clientId: client_id,
      scope: authData.scope
    });

    // Delete used auth code (one-time use)
    storage.authCodes.delete(code);

    return res.json({
      access_token: accessToken,
      refresh_token: newRefreshToken,
      token_type: 'Bearer',
      expires_in: CONFIG.TOKEN_EXPIRY
    });
  }

  // Handle refresh_token grant
  if (grant_type === 'refresh_token') {
    if (!refresh_token) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing refresh_token'
      });
    }

    const refreshData = storage.refreshTokens.get(refresh_token);
    if (!refreshData || refreshData.clientId !== client_id) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid refresh token'
      });
    }

    // Generate new access token
    const accessToken = createAccessToken(refreshData.userId, client_id, refreshData.scope);

    storage.accessTokens.set(accessToken, {
      userId: refreshData.userId,
      clientId: client_id,
      scope: refreshData.scope,
      expiresAt: Date.now() + CONFIG.TOKEN_EXPIRY * 1000
    });

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: CONFIG.TOKEN_EXPIRY
    });
  }

  return res.status(400).json({
    error: 'unsupported_grant_type',
    error_description: 'Only authorization_code and refresh_token grants are supported'
  });
});

/**
 * Token Revocation Endpoint (RFC 7009)
 * POST /oauth/revoke
 * Revokes access or refresh tokens
 */
app.post('/oauth/revoke', (req, res) => {
  const { token, token_type_hint, client_id, client_secret } = req.body;

  if (!verifyClient(client_id, client_secret)) {
    return res.status(401).json({
      error: 'invalid_client'
    });
  }

  if (!token) {
    return res.status(400).json({
      error: 'invalid_request'
    });
  }

  // Try to revoke as both types
  storage.accessTokens.delete(token);
  storage.refreshTokens.delete(token);

  // RFC 7009: Return 200 even if token wasn't found
  res.status(200).json({ success: true });
});

/**
 * Token Info Endpoint (for debugging)
 * GET /oauth/tokeninfo
 * Returns information about an access token
 */
app.get('/oauth/tokeninfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Missing or invalid authorization header'
    });
  }

  const token = authHeader.substring(7);
  const tokenData = verifyAccessToken(token);

  if (!tokenData) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Token is invalid or expired'
    });
  }

  const user = storage.users.get(tokenData.sub);
  res.json({
    user_id: tokenData.sub,
    agent_user_id: user?.profile?.agentUserId,
    email: user?.email,
    client_id: tokenData.client_id,
    scope: tokenData.scope,
    expires_in: tokenData.exp - Math.floor(Date.now() / 1000)
  });
});

/**
 * Middleware to verify access tokens on protected routes
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Missing authorization token'
    });
  }

  const token = authHeader.substring(7);
  const tokenData = verifyAccessToken(token);

  if (!tokenData) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Invalid or expired token'
    });
  }

  req.userId = tokenData.sub;
  req.clientId = tokenData.client_id;
  req.scope = tokenData.scope;
  next();
}

// ========================================
// EXAMPLE PROTECTED ENDPOINT
// ========================================
app.get('/api/user/profile', requireAuth, (req, res) => {
  const user = storage.users.get(req.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({
    agentUserId: user.profile.agentUserId,
    email: user.email,
    name: user.profile.name
  });
});

// ========================================
// SERVER STARTUP
// ========================================
const PORT = process.env.PORT || 5050;

// For production, use HTTPS
const https = require('https');
const fs = require('fs');

// Uncomment for HTTPS in production:
/*
const httpsOptions = {
  key: fs.readFileSync('/path/to/privkey.pem'),
  cert: fs.readFileSync('/path/to/fullchain.pem')
};

https.createServer(httpsOptions, app).listen(443, () => {
  console.log('OAuth2 server running on https://api.darksmart.pro');
});
*/

// For development:
app.listen(PORT, () => {
  console.log(`OAuth2 server running on port ${PORT}`);
  console.log('\nOAuth2 Endpoints:');
  console.log(`- Authorization: GET  ${CONFIG.BASE_URL}/oauth/authorize`);
  console.log(`- Token:         POST ${CONFIG.BASE_URL}/oauth/token`);
  console.log(`- Revoke:        POST ${CONFIG.BASE_URL}/oauth/revoke`);
  console.log(`- Token Info:    GET  ${CONFIG.BASE_URL}/oauth/tokeninfo`);
});

module.exports = app;