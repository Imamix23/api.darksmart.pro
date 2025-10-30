const jwt = require('jsonwebtoken');

const ACCESS_TTL = process.env.JWT_ACCESS_TTL || '1h';
const REFRESH_TTL = process.env.JWT_REFRESH_TTL || '30d';

const signAccessToken = (payload) =>
  jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: ACCESS_TTL, algorithm: 'HS256' });

const signRefreshToken = (payload) =>
  jwt.sign({ ...payload, type: 'refresh' }, process.env.JWT_SECRET, { expiresIn: REFRESH_TTL, algorithm: 'HS256' });

const verifyToken = (token) => jwt.verify(token, process.env.JWT_SECRET);

module.exports = { signAccessToken, signRefreshToken, verifyToken, ACCESS_TTL, REFRESH_TTL };
