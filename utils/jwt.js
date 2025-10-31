const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

/**
 * Generate a JWT token
 * @param {Object} payload - Token payload
 * @param {number} expiresIn - Expiration time in seconds (default: 1 hour)
 * @returns {string} JWT token
 */
function generateToken(payload, expiresIn = 3600) {
  return jwt.sign(
    {
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + expiresIn
    },
    JWT_SECRET
  );
}

/**
 * Verify and decode a JWT token
 * @param {string} token - JWT token to verify
 * @returns {Object|null} Decoded payload or null if invalid
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    console.error('JWT verification failed:', err.message);
    return null;
  }
}

/**
 * Decode token without verification (for inspection only)
 * @param {string} token - JWT token
 * @returns {Object|null} Decoded payload or null
 */
function decodeToken(token) {
  try {
    return jwt.decode(token);
  } catch (err) {
    return null;
  }
}

module.exports = {
  generateToken,
  verifyToken,
  decodeToken
};