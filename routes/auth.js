const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const { query } = require('../database');
const { generateToken, verifyToken } = require('../utils/jwt');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// Signup endpoint
router.post(
  '/signup',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('name').trim().notEmpty().withMessage('Name is required'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password, name } = req.body;

      // Check if user exists
      const existing = await query('SELECT id FROM users WHERE email=$1', [email]);
      if (existing.rows.length > 0) {
        return res.status(400).json({ error: 'Email already registered' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 12);

      // Generate agentUserId for Google Home
      const agentUserId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      // Insert user
      const result = await query(
        `INSERT INTO users (email, password_hash, name, agent_user_id, created_at) 
         VALUES ($1, $2, $3, $4, NOW()) 
         RETURNING id, email, name, agent_user_id`,
        [email, hashedPassword, name, agentUserId]
      );

      const user = result.rows[0];

      // Generate JWT token
      const token = generateToken({
        sub: user.id,
        email: user.email,
        agentUserId: user.agent_user_id
      });

      res.status(201).json({
        message: 'User registered successfully',
        user: {
          id: user.id,
          email: user.email,
          name: user.name
        },
        token
      });
    } catch (err) {
      console.error('Signup error:', err);
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

// Login endpoint
router.post(
  '/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;

      const result = await query(
        'SELECT id, email, password_hash, name, agent_user_id FROM users WHERE email=$1',
        [email]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      const user = result.rows[0];
      const match = await bcrypt.compare(password, user.password_hash);

      if (!match) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Update last login
      await query('UPDATE users SET last_login=NOW() WHERE id=$1', [user.id]);

      // Generate JWT token
      const token = generateToken({
        sub: user.id,
        email: user.email,
        agentUserId: user.agent_user_id
      });

      res.json({
        message: 'Login successful',
        user: {
          id: user.id,
          email: user.email,
          name: user.name
        },
        token
      });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

// Get current user profile
router.get('/me', requireAuth, async (req, res) => {
  try {
    const result = await query(
      'SELECT id, email, name, agent_user_id, created_at FROM users WHERE id=$1',
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// Update user profile
router.put('/me', requireAuth, [
  body('name').optional().trim().notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name } = req.body;
    
    const result = await query(
      'UPDATE users SET name=$1 WHERE id=$2 RETURNING id, email, name',
      [name, req.userId]
    );

    res.json({ 
      message: 'Profile updated',
      user: result.rows[0] 
    });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Change password
router.post('/change-password', requireAuth, [
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 8 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { currentPassword, newPassword } = req.body;

    const result = await query(
      'SELECT password_hash FROM users WHERE id=$1',
      [req.userId]
    );

    const match = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const newHash = await bcrypt.hash(newPassword, 12);
    await query('UPDATE users SET password_hash=$1 WHERE id=$2', [newHash, req.userId]);

    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Logout (client-side token removal, but we can log it)
router.post('/logout', requireAuth, async (req, res) => {
  try {
    // You could implement token blacklisting here if needed
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Logout failed' });
  }
});

module.exports = router;