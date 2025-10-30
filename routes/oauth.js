const express = require('express');
const { body, query: q, validationResult } = require('express-validator');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { withTransaction, query } = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();

const randomToken = (size = 32) => crypto.randomBytes(size).toString('hex');

router.post(
  '/clients',
  auth(),
  [body('name').isString(), body('redirect_uri').isString(), body('scopes').optional().isString()],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const client_id = uuidv4();
      const client_secret = randomToken(24);
      await query(
        'INSERT INTO oauth_clients (client_id, client_secret, redirect_uri, user_id, scopes) VALUES ($1,$2,$3,$4,$5)',
        [client_id, client_secret, req.body.redirect_uri, req.user.id, req.body.scopes || null]
      );
      res.status(201).json({ client_id, client_secret });
    } catch (err) {
      next(err);
    }
  }
);

router.get(
  '/authorize',
  auth(),
  [
    q('response_type').equals('code'),
    q('client_id').isString(),
    q('redirect_uri').isString(),
    q('scope').optional().isString(),
    q('state').optional().isString(),
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const { client_id, redirect_uri, scope, state } = req.query;

      const { rows: clients } = await query('SELECT client_id, redirect_uri FROM oauth_clients WHERE client_id=$1', [
        client_id,
      ]);
      if (!clients.length) return res.status(400).json({ error: 'invalid_client' });
      if (clients[0].redirect_uri !== redirect_uri)
        return res.status(400).json({ error: 'invalid_redirect_uri' });

      const code = randomToken(24);
      const expires_at = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
      await query(
        'INSERT INTO oauth_auth_codes (code, client_id, user_id, redirect_uri, scope, expires_at) VALUES ($1,$2,$3,$4,$5,$6)',
        [code, client_id, req.user.id, redirect_uri, scope || null, expires_at]
      );

      const url = new URL(redirect_uri);
      url.searchParams.set('code', code);
      if (state) url.searchParams.set('state', state);
      return res.redirect(url.toString());
    } catch (err) {
      next(err);
    }
  }
);

router.post(
  '/token',
  [
    body('grant_type').isString(),
    body('client_id').isString(),
    body('client_secret').isString(),
    body('redirect_uri').optional().isString(),
    body('code').optional().isString(),
    body('refresh_token').optional().isString(),
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { grant_type, client_id, client_secret } = req.body;
      const { rows: clients } = await query(
        'SELECT client_id, client_secret FROM oauth_clients WHERE client_id=$1',
        [client_id]
      );
      if (!clients.length || clients[0].client_secret !== client_secret)
        return res.status(401).json({ error: 'invalid_client' });

      if (grant_type === 'authorization_code') {
        const { code, redirect_uri } = req.body;
        const { rows: codes } = await query(
          'SELECT code, user_id, redirect_uri, expires_at FROM oauth_auth_codes WHERE code=$1 AND client_id=$2',
          [code, client_id]
        );
        if (!codes.length) return res.status(400).json({ error: 'invalid_grant' });
        const authCode = codes[0];
        if (authCode.redirect_uri !== redirect_uri) return res.status(400).json({ error: 'invalid_grant' });
        if (new Date(authCode.expires_at).getTime() < Date.now())
          return res.status(400).json({ error: 'invalid_grant' });

        const access_token = randomToken(32);
        const refresh_token = randomToken(32);
        const access_expires_at = new Date(Date.now() + 60 * 60 * 1000); // 1h
        const refresh_expires_at = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30d

        await withTransaction(async (client) => {
          await client.query('DELETE FROM oauth_auth_codes WHERE code=$1', [code]);
          await client.query(
            'INSERT INTO oauth_access_tokens (access_token, client_id, user_id, expires_at) VALUES ($1,$2,$3,$4)',
            [access_token, client_id, authCode.user_id, access_expires_at]
          );
          await client.query(
            'INSERT INTO oauth_refresh_tokens (refresh_token, client_id, user_id, expires_at) VALUES ($1,$2,$3,$4)',
            [refresh_token, client_id, authCode.user_id, refresh_expires_at]
          );
        });

        return res.json({
          token_type: 'Bearer',
          access_token,
          expires_in: 3600,
          refresh_token,
        });
      }

      if (grant_type === 'refresh_token') {
        const { refresh_token } = req.body;
        const { rows: refs } = await query(
          'SELECT refresh_token, user_id, expires_at FROM oauth_refresh_tokens WHERE refresh_token=$1 AND client_id=$2',
          [refresh_token, client_id]
        );
        if (!refs.length) return res.status(400).json({ error: 'invalid_grant' });
        const ref = refs[0];
        if (new Date(ref.expires_at).getTime() < Date.now())
          return res.status(400).json({ error: 'invalid_grant' });

        const access_token = randomToken(32);
        const access_expires_at = new Date(Date.now() + 60 * 60 * 1000);
        const new_refresh_token = randomToken(32);
        const refresh_expires_at = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

        await withTransaction(async (client) => {
          await client.query('DELETE FROM oauth_refresh_tokens WHERE refresh_token=$1 AND client_id=$2', [
            refresh_token,
            client_id,
          ]);
          await client.query(
            'INSERT INTO oauth_access_tokens (access_token, client_id, user_id, expires_at) VALUES ($1,$2,$3,$4)',
            [access_token, client_id, ref.user_id, access_expires_at]
          );
          await client.query(
            'INSERT INTO oauth_refresh_tokens (refresh_token, client_id, user_id, expires_at) VALUES ($1,$2,$3,$4)',
            [new_refresh_token, client_id, ref.user_id, refresh_expires_at]
          );
        });

        return res.json({ token_type: 'Bearer', access_token, expires_in: 3600, refresh_token: new_refresh_token });
      }

      return res.status(400).json({ error: 'unsupported_grant_type' });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;
