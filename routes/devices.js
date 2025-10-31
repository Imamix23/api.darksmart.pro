const express = require('express');
const { body, validationResult } = require('express-validator');
const { query } = require('../database');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// Get all devices for current user
router.get('/', requireAuth, async (req, res) => {
  try {
    const result = await query(
      `SELECT d.*, ds.state, ds.updated_at as state_updated_at
       FROM devices d
       LEFT JOIN device_states ds ON d.id = ds.device_id
       WHERE d.user_id = $1
       ORDER BY d.name`,
      [req.userId]
    );

    res.json({ devices: result.rows });
  } catch (err) {
    console.error('Get devices error:', err);
    res.status(500).json({ error: 'Failed to fetch devices' });
  }
});

// Get single device
router.get('/:id', requireAuth, async (req, res) => {
  try {
    const result = await query(
      `SELECT d.*, ds.state, ds.updated_at as state_updated_at
       FROM devices d
       LEFT JOIN device_states ds ON d.id = ds.device_id
       WHERE d.id = $1 AND d.user_id = $2`,
      [req.params.id, req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    res.json({ device: result.rows[0] });
  } catch (err) {
    console.error('Get device error:', err);
    res.status(500).json({ error: 'Failed to fetch device' });
  }
});

// Add new device
router.post('/', requireAuth, [
  body('deviceId').trim().notEmpty(),
  body('name').trim().notEmpty(),
  body('type').isIn(['action.devices.types.OUTLET', 'action.devices.types.LIGHT', 
                     'action.devices.types.THERMOSTAT', 'action.devices.types.LOCK',
                     'action.devices.types.SWITCH', 'action.devices.types.FAN']),
  body('traits').isArray(),
  body('roomHint').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { deviceId, name, type, traits, attributes, nicknames, roomHint } = req.body;

    // Check if device already exists
    const existing = await query(
      'SELECT id FROM devices WHERE device_id=$1 AND user_id=$2',
      [deviceId, req.userId]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Device already exists' });
    }

    const result = await query(
      `INSERT INTO devices (user_id, device_id, name, type, traits, attributes, nicknames, room_hint, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
       RETURNING *`,
      [
        req.userId,
        deviceId,
        name,
        type,
        JSON.stringify(traits),
        JSON.stringify(attributes || {}),
        JSON.stringify(nicknames || []),
        roomHint || null
      ]
    );

    // Initialize device state
    const initialState = {
      online: true,
      on: false
    };

    await query(
      `INSERT INTO device_states (device_id, state, updated_at)
       VALUES ($1, $2, NOW())`,
      [result.rows[0].id, JSON.stringify(initialState)]
    );

    res.status(201).json({ 
      message: 'Device added successfully',
      device: result.rows[0] 
    });
  } catch (err) {
    console.error('Add device error:', err);
    res.status(500).json({ error: 'Failed to add device' });
  }
});

// Update device
router.put('/:id', requireAuth, [
  body('name').optional().trim().notEmpty(),
  body('nicknames').optional().isArray(),
  body('roomHint').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, nicknames, roomHint } = req.body;
    
    // Build dynamic update query
    const updates = [];
    const values = [];
    let paramIndex = 1;

    if (name) {
      updates.push(`name=$${paramIndex++}`);
      values.push(name);
    }
    if (nicknames) {
      updates.push(`nicknames=$${paramIndex++}`);
      values.push(JSON.stringify(nicknames));
    }
    if (roomHint !== undefined) {
      updates.push(`room_hint=$${paramIndex++}`);
      values.push(roomHint);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(req.params.id, req.userId);

    const result = await query(
      `UPDATE devices 
       SET ${updates.join(', ')}
       WHERE id=$${paramIndex++} AND user_id=$${paramIndex++}
       RETURNING *`,
      values
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    res.json({ 
      message: 'Device updated',
      device: result.rows[0] 
    });
  } catch (err) {
    console.error('Update device error:', err);
    res.status(500).json({ error: 'Failed to update device' });
  }
});

// Update device state
router.post('/:id/state', requireAuth, [
  body('state').isObject()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Verify device belongs to user
    const deviceCheck = await query(
      'SELECT id FROM devices WHERE id=$1 AND user_id=$2',
      [req.params.id, req.userId]
    );

    if (deviceCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    const { state } = req.body;

    const result = await query(
      `INSERT INTO device_states (device_id, state, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (device_id)
       DO UPDATE SET state=$2, updated_at=NOW()
       RETURNING *`,
      [req.params.id, JSON.stringify(state)]
    );

    res.json({ 
      message: 'Device state updated',
      state: result.rows[0] 
    });
  } catch (err) {
    console.error('Update state error:', err);
    res.status(500).json({ error: 'Failed to update device state' });
  }
});

// Delete device
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const result = await query(
      'DELETE FROM devices WHERE id=$1 AND user_id=$2 RETURNING id',
      [req.params.id, req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    res.json({ message: 'Device deleted successfully' });
  } catch (err) {
    console.error('Delete device error:', err);
    res.status(500).json({ error: 'Failed to delete device' });
  }
});

module.exports = router;