'use strict';
// Web Companion API: accounts, sessions and per-user data. Runs separately from the frontend.
const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const SESSION_DAYS = 30;
const FRONTEND_ORIGIN = (process.env.FRONTEND_ORIGIN || '').replace(/\/$/, '');
const STARTED = Date.now();
const log = (...a) => console.log(new Date().toISOString(), ...a);
const warn = (...a) => console.error(new Date().toISOString(), ...a);

if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is not set.'); process.exit(1); }

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: true },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 8000
});
// A dropped idle connection is logged and replaced by the pool instead of crashing the process.
pool.on('error', e => warn('Idle database connection error (recovering):', e.message));

let dbOk = false;
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS app_state (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  data jsonb NOT NULL,
  updated_at timestamptz NOT NULL
);`;

const ensureSchema = () => pool.query(SCHEMA);
async function checkDb() {
  try {
    await pool.query('SELECT 1');
    if (!dbOk) log('Database connection restored.');
    dbOk = true;
  } catch (e) {
    if (dbOk) warn('Database check failed:', e.message);
    dbOk = false;
  }
  return dbOk;
}
// Startup self-repair: retry with backoff, then exit so the host restarts the service.
async function connectWithRetry() {
  for (let attempt = 1; attempt <= 10; attempt++) {
    try { await ensureSchema(); dbOk = true; log('Database ready.'); return; }
    catch (e) {
      warn(`Database not ready (attempt ${attempt} of 10):`, e.message);
      await new Promise(r => setTimeout(r, Math.min(30000, 1000 * 2 ** attempt)));
    }
  }
  throw new Error('Database unavailable after 10 attempts.');
}

const app = express();
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store' });
  const origin = req.headers.origin;
  if (FRONTEND_ORIGIN && origin === FRONTEND_ORIGIN) {
    res.set({
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
      'Vary': 'Origin'
    });
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});
app.use(express.json({ limit: '5mb' }));

const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const hash = t => crypto.createHash('sha256').update(t).digest('hex');
const normEmail = v => String(v || '').trim().toLowerCase();
const validEmail = e => e.length <= 254 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
const bearer = req => { const h = req.headers.authorization || ''; return h.startsWith('Bearer ') ? h.slice(7) : ''; };

const hits = new Map();
function limiter(max, windowMs) {
  return (req, res, next) => {
    const key = req.ip + req.path, now = Date.now();
    const recent = (hits.get(key) || []).filter(t => now - t < windowMs);
    if (recent.length >= max) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
    recent.push(now); hits.set(key, recent); next();
  };
}
setInterval(() => hits.clear(), 60 * 60e3).unref();

async function startSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  await pool.query(
    `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '${SESSION_DAYS} days')`,
    [hash(token), userId]
  );
  return token;
}

async function requireUser(req, res, next) {
  const token = bearer(req);
  if (!token) return res.status(401).json({ error: 'Sign in to continue.' });
  const { rows: [u] } = await pool.query(
    'SELECT u.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > now()',
    [hash(token)]
  );
  if (!u) return res.status(401).json({ error: 'Your session has ended. Sign in again.' });
  req.user = u;
  next();
}

app.get('/', (req, res) => res.json({ service: 'web-companion-api', status: 'running' }));

app.get('/api/health', wrap(async (req, res) => {
  const ok = await checkDb();
  res.status(ok ? 200 : 503).json({ ok, uptimeSec: Math.round((Date.now() - STARTED) / 1000) });
}));

app.post('/api/signup', limiter(20, 15 * 60e3), wrap(async (req, res) => {
  const email = normEmail(req.body.email), password = String(req.body.password || '');
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8 || password.length > 200) return res.status(400).json({ error: 'Use a password of 8 to 200 characters.' });
  const hashed = await bcrypt.hash(password, 12);
  let row;
  try {
    ({ rows: [row] } = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email', [email, hashed]));
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'An account with this email already exists. Sign in instead.' });
    throw e;
  }
  const token = await startSession(row.id);
  res.status(201).json({ email: row.email, token });
}));

app.post('/api/login', limiter(20, 15 * 60e3), wrap(async (req, res) => {
  const email = normEmail(req.body.email), password = String(req.body.password || '');
  const { rows: [u] } = await pool.query('SELECT id, email, password_hash FROM users WHERE email = $1', [email]);
  const ok = u && await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(401).json({ error: 'Email or password is incorrect.' });
  const token = await startSession(u.id);
  res.json({ email: u.email, token });
}));

app.post('/api/logout', wrap(async (req, res) => {
  const token = bearer(req);
  if (token) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [hash(token)]);
  res.json({ ok: true });
}));

app.get('/api/me', wrap(requireUser), (req, res) => res.json({ email: req.user.email }));

app.get('/api/state', wrap(requireUser), wrap(async (req, res) => {
  const { rows: [row] } = await pool.query('SELECT data, updated_at FROM app_state WHERE user_id = $1', [req.user.id]);
  res.json(row ? { data: row.data, updatedAt: row.updated_at.getTime() } : { data: null, updatedAt: 0 });
}));

// Last write wins: an older copy never overwrites a newer one.
app.put('/api/state', wrap(requireUser), wrap(async (req, res) => {
  const data = req.body.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) return res.status(400).json({ error: 'Invalid data.' });
  const ts = new Date(Math.min(Number(req.body.updatedAt) || Date.now(), Date.now() + 60e3));
  await pool.query(
    `INSERT INTO app_state (user_id, data, updated_at) VALUES ($1, $2, $3)
     ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at
     WHERE app_state.updated_at < EXCLUDED.updated_at`,
    [req.user.id, JSON.stringify(data), ts]
  );
  res.json({ ok: true });
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

// Error handling: client mistakes get their status, database outages get 503 with a retry hint.
const DB_DOWN = /ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|Connection terminated|timeout|^57P|^08/;
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err.status && err.status < 500) return res.status(err.status).json({ error: err.status === 400 ? 'Invalid request.' : err.message });
  const dbDown = DB_DOWN.test(`${err.code || ''} ${err.message || ''}`);
  if (dbDown) { dbOk = false; warn('Database temporarily unavailable:', err.message); }
  else warn('Request failed:', err.stack || err.message);
  res.status(dbDown ? 503 : 500).set('Retry-After', '5').json({
    error: dbDown ? 'Database is waking up. Try again in a few seconds.' : 'Something went wrong. Try again.'
  });
});

// Process-level safety net.
process.on('unhandledRejection', r => warn('Unhandled promise rejection (kept running):', (r && r.message) || r));
process.on('uncaughtException', e => { warn('Fatal error, exiting so the host restarts the service:', e.stack || e.message); process.exit(1); });
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => { log('Shutting down.'); pool.end().finally(() => process.exit(0)); });
}

app.listen(PORT, () => log(`Web Companion API listening on port ${PORT}`));
connectWithRetry().catch(e => { warn(e.message); process.exit(1); });
// Periodic self-check, and schema repair if a table was dropped.
setInterval(checkDb, 60e3).unref();
setInterval(() => { if (dbOk) ensureSchema().catch(e => warn('Schema repair failed:', e.message)); }, 10 * 60e3).unref();
