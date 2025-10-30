const express = require('express');
const { body, param, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const auth = require('../middleware/auth');
const { query } = require('../db');

const router = express.Router();

router.use(auth());

router.post(
  '/',
  [
    body('name').isString(),
    body('type').isString(),
    body('traits').optional().isObject(),
    body('metadata').optional().isObject(),
    body('state').optional().isObject(),
    body('agent_user_id').optional().isString(),
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const id = uuidv4();
      const {
        name,
        type,
        traits = {},
        metadata = {},
        state = {},
        agent_user_id = null,
      } = req.body;
      await query(
        'INSERT INTO devices (id, user_id, agent_user_id, name, type, traits, metadata, state) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [id, req.user.id, agent_user_id, name, type, traits, metadata, state]
      );
      res.status(201).json({ id, name, type, traits, metadata, state, agent_user_id, user_id: req.user.id });
    } catch (err) {
      next(err);
    }
  }
);

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await query('SELECT * FROM devices WHERE user_id=$1 ORDER BY created_at DESC NULLS LAST', [
      req.user.id,
    ]);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

router.patch(
  '/:id',
  [param('id').isString(), body().custom((v) => typeof v === 'object' && v !== null)],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const { id } = req.params;

      const { rows: owns } = await query('SELECT id FROM devices WHERE id=$1 AND user_id=$2', [id, req.user.id]);
      if (!owns.length) return res.status(404).json({ error: 'Device not found' });

      const allowed = ['name', 'traits', 'metadata', 'state', 'type', 'agent_user_id'];
      const sets = [];
      const values = [];
      let i = 1;
      for (const key of allowed) {
        if (key in req.body) {
          sets.push(`${key}=$${i++}`);
          values.push(req.body[key]);
        }
      }
      if (!sets.length) return res.status(400).json({ error: 'No updatable fields provided' });
      values.push(id, req.user.id);
      await query(`UPDATE devices SET ${sets.join(', ')}, updated_at=NOW() WHERE id=$${i++} AND user_id=$${i}`, values);

      const { rows } = await query('SELECT * FROM devices WHERE id=$1', [id]);
      res.json(rows[0]);
    } catch (err) {
      next(err);
    }
  }
);

router.delete('/:id', [param('id').isString()], async (req, res, next) => {
  try {
    const { id } = req.params;
    const { rowCount } = await query('DELETE FROM devices WHERE id=$1 AND user_id=$2', [id, req.user.id]);
    if (!rowCount) return res.status(404).json({ error: 'Device not found' });
    res.status(204).send();
  } catch (err) {
    next(err);
  }
});

module.exports = router;
