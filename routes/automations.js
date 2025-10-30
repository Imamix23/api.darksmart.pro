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
    body('trigger').isObject(),
    body('action').isObject(),
    body('conditions').optional().isObject(),
    body('enabled').optional().isBoolean(),
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const id = uuidv4();
      const { name, trigger, action, conditions = {}, enabled = true } = req.body;
      await query(
        'INSERT INTO automations (id, user_id, name, trigger, action, conditions, enabled) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [id, req.user.id, name, trigger, action, conditions, enabled]
      );
      res.status(201).json({ id, user_id: req.user.id, name, trigger, action, conditions, enabled });
    } catch (err) {
      next(err);
    }
  }
);

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await query('SELECT * FROM automations WHERE user_id=$1 ORDER BY created_at DESC NULLS LAST', [
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

      const { rows: owns } = await query('SELECT id FROM automations WHERE id=$1 AND user_id=$2', [
        id,
        req.user.id,
      ]);
      if (!owns.length) return res.status(404).json({ error: 'Automation not found' });

      const allowed = ['name', 'trigger', 'action', 'conditions', 'enabled'];
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
      await query(`UPDATE automations SET ${sets.join(', ')}, updated_at=NOW() WHERE id=$${i++} AND user_id=$${i}`, values);

      const { rows } = await query('SELECT * FROM automations WHERE id=$1', [id]);
      res.json(rows[0]);
    } catch (err) {
      next(err);
    }
  }
);

router.delete('/:id', [param('id').isString()], async (req, res, next) => {
  try {
    const { id } = req.params;
    const { rowCount } = await query('DELETE FROM automations WHERE id=$1 AND user_id=$2', [id, req.user.id]);
    if (!rowCount) return res.status(404).json({ error: 'Automation not found' });
    res.status(204).send();
  } catch (err) {
    next(err);
  }
});

module.exports = router;
