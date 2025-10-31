const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { query } = require('../database');
const { generateToken: generateJWT, verifyToken } = require('../utils/jwt');

const router = express.Router();

const CONFIG = {
  JWT_SECRET: process.env.JWT_SECRET,
  TOKEN_EXPIRY: 3600,
  REFRESH_TOKEN_EXPIRY: 30 * 24 * 60 * 60,
  OAUTH_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
  OAUTH_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
  BASE_URL: process.env.BASE_URL || 'https://api.darksmart.pro'
};

// Helper: Generate secure token
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('base64url');
}

// Helper: Verify client
function verifyClient(clientId, clientSecret = null) {
  if (clientId !== CONFIG.OAUTH_CLIENT_ID) return false;
  if (clientSecret && clientSecret !== CONFIG.OAUTH_CLIENT_SECRET) return false;
  return true;
}

// OAuth Authorization Endpoint
router.get('/authorize', async (req, res) => {
  const { client_id, redirect_uri, state, response_type, scope } = req.query;

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

  // Store OAuth session
  const sessionId = generateToken(16);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  await query(
    `INSERT INTO oauth_sessions (session_id, client_id, redirect_uri, state, scope, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [sessionId, client_id, redirect_uri, state, scope || 'openid email profile', expiresAt]
  );

  // Render authorization page
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>DarkSmart Authorization</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 20px;
        }
        .container {
          background: white;
          padding: 2.5rem;
          border-radius: 16px;
          box-shadow: 0 20px 60px rgba(0,0,0,0.2);
          max-width: 440px;
          width: 100%;
        }
        h1 {
          font-size: 1.75rem;
          margin-bottom: 0.5rem;
          color: #1a202c;
        }
        .subtitle {
          color: #718096;
          margin-bottom: 2rem;
          font-size: 0.95rem;
        }
        .scope-list {
          background: #f7fafc;
          padding: 1.25rem;
          border-radius: 12px;
          margin-bottom: 2rem;
          border: 1px solid #e2e8f0;
        }
        .scope-item {
          display: flex;
          align-items: center;
          padding: 0.5rem 0;
          color: #2d3748;
          font-size: 0.9rem;
        }
        .scope-item::before {
          content: "✓";
          color: #48bb78;
          font-weight: bold;
          margin-right: 0.75rem;
          font-size: 1.1rem;
        }
        input {
          width: 100%;
          padding: 0.875rem;
          margin-bottom: 1rem;
          border: 2px solid #e2e8f0;
          border-radius: 8px;
          font-size: 1rem;
          transition: border-color 0.2s;
        }
        input:focus {
          outline: none;
          border-color: #667eea;
        }
        button {
          width: 100%;
          padding: 0.875rem;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 1rem;
          font-weight: 600;
          cursor: pointer;
          transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
          transform: translateY(-2px);
          box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        button:active {
          transform: translateY(0);
        }
        .error {
          color: #e53e3e;
          font-size: 0.9rem;
          margin-top: 1rem;
          padding: 0.75rem;
          background: #fff5f5;
          border-radius: 8px;
          display: none;
        }
        .demo-info {
          margin-top: 1.5rem;
          padding: 1rem;
          background: #ebf8ff;
          border-radius: 8px;
          font-size: 0.85rem;
          color: #2c5282;
          border: 1px solid #bee3f8;
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

        <form id="authForm">
          <input type="email" name="email" placeholder="Email" required autocomplete="email">
          <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
          <button type="submit">Authorize</button>
          <div class="error" id="error"></div>
        </form>

        <div class="demo-info">
          <strong>Testing?</strong> Use your DarkSmart account credentials to authorize.
        </div>
      </div>

      <script>
        document.getElementById('authForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const error = document.getElementById('error');
          const formData = new FormData(e.target);
          formData.append('session_id', '${sessionId}');
          
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

// OAuth Authorization POST Handler
router.post('/authorize', async (req, res) => {
  try {
    const { session_id, email, password } = req.body;

    // Get session
    const sessionResult = await query(
      'SELECT * FROM oauth_sessions WHERE session_id=$1 AND expires_at > NOW()',
      [session_id]
    );

    if (sessionResult.rows.length === 0) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Session expired or invalid'
      });
    }

    const session = sessionResult.rows[0];

    // Authenticate user
    const userResult = await query(
      'SELECT id, password_hash, agent_user_id FROM users WHERE email=$1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        error: 'access_denied',
        error_description: 'Invalid credentials'
      });
    }

    const user = userResult.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.status(401).json({
        error: 'access_denied',
        error_description: 'Invalid credentials'
      });
    }

    // Generate authorization code
    const authCode = generateToken(32);
    const codeExpiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await query(
      `INSERT INTO oauth_auth_codes (code, user_id, client_id, redirect_uri, scope, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [authCode, user.id, session.client_id, session.redirect_uri, session.scope, codeExpiresAt]
    );

    // Clean up session
    await query('DELETE FROM oauth_sessions WHERE session_id=$1', [session_id]);

    // Build redirect URL
    const redirectUrl = new URL(session.redirect_uri);
    redirectUrl.searchParams.set('code', authCode);
    redirectUrl.searchParams.set('state', session.state);

    res.json({ redirect_uri: redirectUrl.toString() });
  } catch (err) {
    console.error('OAuth authorize error:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// OAuth Token Endpoint
router.post('/token', async (req, res) => {
  try {
    const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;

    if (!verifyClient(client_id, client_secret)) {
      return res.status(401).json({ error: 'invalid_client' });
    }

    // Handle authorization_code grant
    if (grant_type === 'authorization_code') {
      const codeResult = await query(
        'SELECT * FROM oauth_auth_codes WHERE code=$1 AND expires_at > NOW()',
        [code]
      );

      if (codeResult.rows.length === 0) {
        return res.status(400).json({ error: 'invalid_grant' });
      }

      const authCode = codeResult.rows[0];

      if (authCode.client_id !== client_id || authCode.redirect_uri !== redirect_uri) {
        return res.status(400).json({ error: 'invalid_grant' });
      }

      // Get user info
      const userResult = await query(
        'SELECT id, email, agent_user_id FROM users WHERE id=$1',
        [authCode.user_id]
      );
      const user = userResult.rows[0];

      // Generate tokens
      const accessToken = generateJWT({
        sub: user.id,
        email: user.email,
        agentUserId: user.agent_user_id,
        client_id: client_id,
        scope: authCode.scope
      }, CONFIG.TOKEN_EXPIRY);

      const newRefreshToken = generateToken(32);
      const refreshExpiresAt = new Date(Date.now() + CONFIG.REFRESH_TOKEN_EXPIRY * 1000);

      // Store tokens
      await query(
        `INSERT INTO oauth_refresh_tokens (token, user_id, client_id, scope, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [newRefreshToken, user.id, client_id, authCode.scope, refreshExpiresAt]
      );

      // Delete used code
      await query('DELETE FROM oauth_auth_codes WHERE code=$1', [code]);

      return res.json({
        access_token: accessToken,
        refresh_token: newRefreshToken,
        token_type: 'Bearer',
        expires_in: CONFIG.TOKEN_EXPIRY
      });
    }

    // Handle refresh_token grant
    if (grant_type === 'refresh_token') {
      const tokenResult = await query(
        'SELECT * FROM oauth_refresh_tokens WHERE token=$1 AND expires_at > NOW()',
        [refresh_token]
      );

      if (tokenResult.rows.length === 0 || tokenResult.rows[0].client_id !== client_id) {
        return res.status(400).json({ error: 'invalid_grant' });
      }

      const refreshData = tokenResult.rows[0];
      const userResult = await query(
        'SELECT id, email, agent_user_id FROM users WHERE id=$1',
        [refreshData.user_id]
      );
      const user = userResult.rows[0];

      const accessToken = generateJWT({
        sub: user.id,
        email: user.email,
        agentUserId: user.agent_user_id,
        client_id: client_id,
        scope: refreshData.scope
      }, CONFIG.TOKEN_EXPIRY);

      return res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: CONFIG.TOKEN_EXPIRY
      });
    }

    res.status(400).json({ error: 'unsupported_grant_type' });
  } catch (err) {
    console.error('Token error:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// Token Revocation
router.post('/revoke', async (req, res) => {
  try {
    const { token, client_id, client_secret } = req.body;

    if (!verifyClient(client_id, client_secret)) {
      return res.status(401).json({ error: 'invalid_client' });
    }

    await query('DELETE FROM oauth_refresh_tokens WHERE token=$1', [token]);
    res.json({ success: true });
  } catch (err) {
    console.error('Revoke error:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

module.exports = router;