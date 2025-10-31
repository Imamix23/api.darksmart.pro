const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { Pool } = require('pg');
require('dotenv').config();

if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = `postgres://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`;
}
const router = express.Router();

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Signup route
router.post(
  '/signup',
  [
    body('email').isEmail(),
    body('password').isLength({ min: 6 }),
    body('name').notEmpty(),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password, name } = req.body;

      // Check if user exists
      const existing = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
      if (existing.rows.length > 0) {
        return res.status(400).json({ message: 'Email already registered' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert user
      const result = await pool.query(
        'INSERT INTO users (email, password_hash, name, created_at) VALUES ($1,$2,$3,NOW()) RETURNING id,email,name',
        [email, hashedPassword, name]
      );

      res.status(201).json({
        message: 'User registered successfully',
        user: result.rows[0],
      });
    } catch (err) {
      console.error('Signup error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Login route
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { sub: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ access_token: token, token_type: 'Bearer', expires_in: 3600 });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
