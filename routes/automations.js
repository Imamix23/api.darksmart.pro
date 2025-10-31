const express = require('express');
const { body, validationResult } = require('express-validator');
const { query } = require('../database');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// Get all automations for user
router.get('/', requireAuth, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM automations WHERE user_id=$1 ORDER BY created_at DESC`,
      [req.userId]
    );
    res.json({ automations: result.rows });
  } catch (err) {
    console.error('Get automations error:', err);
    res.status(500).json({ error: 'Failed to fetch automations' });
  }
});

// Get single automation
router.get('/:id', requireAuth, async (req, res) => {
  try {
    const result = await query(
      'SELECT * FROM automations WHERE id=$1 AND user_id=$2',
      [req.params.id, req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Automation not found' });
    }

    res.json({ automation: result.rows[0] });
  } catch (err) {
    console.error('Get automation error:', err);
    res.status(500).json({ error: 'Failed to fetch automation' });
  }
});

// Create automation
router.post('/', requireAuth, [
  body('name').trim().notEmpty(),
  body('trigger').isObject(),
  body('actions').isArray().notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, description, trigger, conditions, actions, enabled } = req.body;

    const result = await query(
      `INSERT INTO automations (user_id, name, description, trigger, conditions, actions, enabled, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING *`,
      [
        req.userId,
        name,
        description || null,
        JSON.stringify(trigger),
        JSON.stringify(conditions || []),
        JSON.stringify(actions),
        enabled !== false
      ]
    );

    res.status(201).json({
      message: 'Automation created',
      automation: result.rows[0]
    });
  } catch (err) {
    console.error('Create automation error:', err);
    res.status(500).json({ error: 'Failed to create automation' });
  }
});

// Update automation
router.put('/:id', requireAuth, async (req, res) => {
  try {
    const { name, description, trigger, conditions, actions, enabled } = req.body;

    const updates = [];
    const values = [];
    let paramIndex = 1;

    if (name) {
      updates.push(`name=$${paramIndex++}`);
      values.push(name);
    }
    if (description !== undefined) {
      updates.push(`description=$${paramIndex++}`);
      values.push(description);
    }
    if (trigger) {
      updates.push(`trigger=$${paramIndex++}`);
      values.push(JSON.stringify(trigger));
    }
    if (conditions) {
      updates.push(`conditions=$${paramIndex++}`);
      values.push(JSON.stringify(conditions));
    }
    if (actions) {
      updates.push(`actions=$${paramIndex++}`);
      values.push(JSON.stringify(actions));
    }
    if (enabled !== undefined) {
      updates.push(`enabled=$${paramIndex++}`);
      values.push(enabled);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(req.params.id, req.userId);

    const result = await query(
      `UPDATE automations SET ${updates.join(', ')}
       WHERE id=$${paramIndex++} AND user_id=$${paramIndex++}
       RETURNING *`,
      values
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Automation not found' });
    }

    res.json({
      message: 'Automation updated',
      automation: result.rows[0]
    });
  } catch (err) {
    console.error('Update automation error:', err);
    res.status(500).json({ error: 'Failed to update automation' });
  }
});

// Toggle automation enabled state
router.patch('/:id/toggle', requireAuth, async (req, res) => {
  try {
    const result = await query(
      `UPDATE automations SET enabled = NOT enabled
       WHERE id=$1 AND user_id=$2
       RETURNING *`,
      [req.params.id, req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Automation not found' });
    }

    res.json({
      message: 'Automation toggled',
      automation: result.rows[0]
    });
  } catch (err) {
    console.error('Toggle automation error:', err);
    res.status(500).json({ error: 'Failed to toggle automation' });
  }
});

// Delete automation
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const result = await query(
      'DELETE FROM automations WHERE id=$1 AND user_id=$2 RETURNING id',
      [req.params.id, req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Automation not found' });
    }

    res.json({ message: 'Automation deleted' });
  } catch (err) {
    console.error('Delete automation error:', err);
    res.status(500).json({ error: 'Failed to delete automation' });
  }
});

module.exports = router;