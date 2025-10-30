const express = require('express');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const { query } = require('../db');
const { hashPassword, comparePassword } = require('../utils/hash');
const { signAccessToken, signRefreshToken, verifyToken } = require('../utils/jwt');
const { OAuth2Client } = require('google-auth-library');

const router = express.Router();

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

router.post(
  '/signup',
  [body('email').isEmail(), body('password').isLength({ min: 8 }), body('name').optional().isString()],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { email, password, name } = req.body;
      const lowerEmail = String(email).toLowerCase();
      const existing = await query('SELECT id FROM users WHERE email = $1', [lowerEmail]);
      if (existing.rowCount) return res.status(409).json({ error: 'Email already registered' });

      const password_hash = await hashPassword(password);
      const id = uuidv4();
      await query(
        'INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, $3, $4)',
        [id, lowerEmail, password_hash, name || null]
      );

      const accessToken = signAccessToken({ id, email: lowerEmail });
      const refreshToken = signRefreshToken({ id, email: lowerEmail });
      return res.status(201).json({ user: { id, email: lowerEmail, name: name || null }, accessToken, refreshToken });
    } catch (err) {
      return next(err);
    }
  }
);

router.post(
  '/signin',
  [body('email').isEmail(), body('password').isString()],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const { email, password } = req.body;
      const lowerEmail = String(email).toLowerCase();

      const { rows } = await query('SELECT id, email, password_hash, name FROM users WHERE email = $1', [lowerEmail]);
      if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

      const user = rows[0];
      const ok = user.password_hash && (await comparePassword(password, user.password_hash));
      if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

      const accessToken = signAccessToken({ id: user.id, email: user.email });
      const refreshToken = signRefreshToken({ id: user.id, email: user.email });
      return res.json({ user: { id: user.id, email: user.email, name: user.name }, accessToken, refreshToken });
    } catch (err) {
      return next(err);
    }
  }
);

router.post('/google', [body('idToken').isString()], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { idToken } = req.body;

    const ticket = await googleClient.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = String(payload.email).toLowerCase();
    const name = payload.name || null;

    let { rows } = await query('SELECT id, email, name FROM users WHERE email = $1', [email]);
    let user;
    if (!rows.length) {
      const id = uuidv4();
      await query('INSERT INTO users (id, email, password_hash, name) VALUES ($1,$2,$3,$4)', [id, email, null, name]);
      user = { id, email, name };
    } else {
      user = rows[0];
    }

    const accessToken = signAccessToken({ id: user.id, email: user.email });
    const refreshToken = signRefreshToken({ id: user.id, email: user.email });
    return res.json({ user, accessToken, refreshToken });
  } catch (err) {
    return next(err);
  }
});

router.post('/refresh', [body('refreshToken').isString()], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { refreshToken } = req.body;
    let payload;
    try {
      payload = verifyToken(refreshToken);
      if (payload.type !== 'refresh') throw new Error('Not a refresh token');
    } catch (e) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    const accessToken = signAccessToken({ id: payload.id, email: payload.email });
    const newRefreshToken = signRefreshToken({ id: payload.id, email: payload.email });
    return res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (err) {
    return next(err);
  }
});

router.get('/me', async (req, res, next) => {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    let payload;
    try {
      payload = verifyToken(token);
    } catch (e) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    const { rows } = await query('SELECT id, email, name FROM users WHERE id=$1', [payload.id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    return res.json(rows[0]);
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
