const { Pool } = require('pg');
const crypto = require('crypto');
require('dotenv').config();

// Retry/backoff configuration
const DEFAULT_MAX_RETRIES = Number(process.env.PG_MAX_RETRIES || 5);
const DEFAULT_INITIAL_DELAY_MS = Number(process.env.PG_INITIAL_DELAY_MS || 500);
const DEFAULT_MAX_DELAY_MS = Number(process.env.PG_MAX_DELAY_MS || 10000);

// Build connection config from either DATABASE_URL or discrete vars
const databaseUrl = process.env.DATABASE_URL || '';
if (!databaseUrl) {
  console.warn('[db] DATABASE_URL not set. Falling back to discrete DB_* variables.');
}

// Validate and normalize discrete vars if no DATABASE_URL
let poolConfig;
if (databaseUrl) {
  poolConfig = {
    connectionString: databaseUrl
  };
} else {
  const user = process.env.DB_USER;
  const password = process.env.DB_PASSWORD;
  const host = process.env.DB_HOST || 'localhost';
  const parsedPort = Number(process.env.DB_PORT);
  const port = Number.isFinite(parsedPort) ? parsedPort : 5432;
  const database = process.env.DB_NAME;

  if (!user || !database) {
    throw new Error('[db] Missing required DB_USER or DB_NAME when DATABASE_URL is not set.');
  }
  if (password === undefined) {
    console.warn('[db] DB_PASSWORD is undefined. Set it in your .env');
  } else if (typeof password !== 'string') {
    // Force to string to satisfy pg client and avoid SASL error
    console.warn('[db] Coercing DB_PASSWORD to string to satisfy driver.');
  }

  poolConfig = {
    user,
    ...(password !== undefined ? { password: String(password) } : {}),
    host,
    port,
    database
  };
}

// Common pool options
poolConfig.ssl = process.env.PGSSL === 'require' ? { rejectUnauthorized: false } : false;
poolConfig.max = Number(process.env.PG_POOL_MAX || 10);
poolConfig.idleTimeoutMillis = Number(process.env.PG_IDLE_TIMEOUT || 30000);
poolConfig.connectionTimeoutMillis = Number(process.env.PG_CONN_TIMEOUT || 5000);

const pool = new Pool(poolConfig);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function jitter(delay) {
  // Full jitter strategy
  return Math.floor(Math.random() * delay);
}

async function ensureConnectivity({ maxRetries = DEFAULT_MAX_RETRIES, initialDelayMs = DEFAULT_INITIAL_DELAY_MS, maxDelayMs = DEFAULT_MAX_DELAY_MS } = {}) {
  let attempt = 0;
  let delay = initialDelayMs;

  while (attempt <= maxRetries) {
    try {
      const client = await pool.connect();
      try {
        await client.query('SELECT 1');
        if (attempt > 0) {
          console.info(`[db] Connected after retry attempt ${attempt}`);
        } else {
          console.info('[db] Connected');
        }
        return; // success
      } finally {
        client.release();
      }
    } catch (err) {
      attempt += 1;
      const code = err && err.code ? ` code=${err.code}` : '';
      const msg = err && err.message ? err.message : String(err);
      if (attempt > maxRetries) {
        console.error(`[db] Connection failed permanently after ${attempt - 1} retries:${code} msg=${msg}`);
        throw err;
      }
      const nextDelay = Math.min(delay * 2, maxDelayMs);
      const wait = jitter(nextDelay);
      console.warn(`[db] Connection attempt ${attempt} failed:${code} msg=${msg}. Retrying in ${wait}ms...`);
      await sleep(wait);
      delay = nextDelay;
    }
  }
}

// Kick off connectivity check on module load but don't block requires
const startupId = crypto.randomBytes(4).toString('hex');
ensureConnectivity().catch((err) => {
  console.error(`[db] Startup connectivity check failed (id=${startupId}). Further queries will retry on demand.`, err);
});

async function query(text, params) {
  // Attempt simple query with retry on connection errors
  let attempt = 0;
  let delay = DEFAULT_INITIAL_DELAY_MS;
  while (true) {
    try {
      return await pool.query(text, params);
    } catch (err) {
      const transient = isTransientError(err);
      if (!transient || attempt >= DEFAULT_MAX_RETRIES) {
        throw err;
      }
      attempt += 1;
      const nextDelay = Math.min(delay * 2, DEFAULT_MAX_DELAY_MS);
      const wait = jitter(nextDelay);
      console.warn(`[db] query retry ${attempt} in ${wait}ms due to transient error: ${err.code || err.message}`);
      await sleep(wait);
      delay = nextDelay;
    }
  }
}

function isTransientError(err) {
  if (!err) return false;
  const codes = new Set([
    'ECONNRESET',
    'ECONNREFUSED',
    'EPIPE',
    'ETIMEDOUT',
    '57P01', // admin_shutdown
    '57P02', // crash_shutdown
    '57P03', // cannot_connect_now
    '53300', // too_many_connections
    '08006', // connection_failure
    '08001', // sqlclient_unable_to_establish_sqlconnection
    '08003', // connection_does_not_exist
    '08000', // connection_exception
    '08004', // sqlserver_rejected_establishment_of_sqlconnection
    '08007', // transaction_resolution_unknown
    '08P01' // protocol_violation
  ]);
  return codes.has(err.code) || /Connection terminated|terminating connection|Connection refused|Client has encountered a connection error|Connection terminated unexpectedly/i.test(err.message || '');
}

async function getClient() {
  // Ensure connectivity before returning a client
  await ensureConnectivity();
  return pool.connect();
}

module.exports = {
  pool,
  query,
  getClient
};
