const express  = require('express');
const fs       = require('fs');
const path     = require('path');
const https    = require('https');
const http     = require('http');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');

const app      = express();
const PORT     = process.env.PORT || 3000;
const APP_URL  = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
const DB_FILE  = path.join(__dirname, 'data', 'db.json');

const JWT_SECRET       = process.env.JWT_SECRET || 'CHANGE_THIS_SECRET_IN_PRODUCTION_ENV';
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET_KEY || '';
const SALT_ROUNDS      = 12;

// ── Ensure data dir exists ────────────────────────────────────────────────
if (!fs.existsSync(path.join(__dirname, 'data')))
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Security headers ──────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// ── In-memory rate limiter ────────────────────────────────────────────────
const _rateBuckets = new Map();
setInterval(() => {
  const cut = Date.now() - 30 * 60 * 1000;
  for (const [k, arr] of _rateBuckets)
    _rateBuckets.set(k, arr.filter(t => t > cut));
}, 10 * 60 * 1000);

function rateLimit(windowMs, max) {
  return (req, res, next) => {
    const key = req.ip + ':' + req.path;
    const now = Date.now();
    const win = now - windowMs;
    const hits = (_rateBuckets.get(key) || []).filter(t => t > win);
    hits.push(now);
    _rateBuckets.set(key, hits);
    if (hits.length > max)
      return res.status(429).json({ error: 'Too many requests — slow down.' });
    next();
  };
}

// ── DATABASE ──────────────────────────────────────────────────────────────
function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    const init = { users: [], userData: {} };
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
    return init;
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { users: [], userData: {} }; }
}
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}
function userSlot(db, uid) {
  if (!db.userData[uid])
    db.userData[uid] = { todos: [], reminders: [], progress: {}, notes: '' };
  return db.userData[uid];
}

// ── reCAPTCHA ─────────────────────────────────────────────────────────────
function verifyRecaptcha(token) {
  return new Promise((resolve, reject) => {
    if (!RECAPTCHA_SECRET) {
      console.warn('[reCAPTCHA] No secret key — bypassing (dev mode)');
      return resolve(true);
    }
    const body = `secret=${encodeURIComponent(RECAPTCHA_SECRET)}&response=${encodeURIComponent(token)}`;
    const req = https.request({
      hostname: 'www.google.com',
      path: '/recaptcha/api/siteverify',
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve(JSON.parse(d).success === true); }
        catch { reject(new Error('Bad reCAPTCHA response')); }
      });
    });
    req.on('error', reject);
    req.write(body); req.end();
  });
}

// ── JWT middleware ────────────────────────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer '))
    return res.status(401).json({ error: 'Login required.' });
  try {
    const decoded = jwt.verify(h.slice(7), JWT_SECRET);
    req.userId   = decoded.userId;
    req.username = decoded.username;
    next();
  } catch(e) {
    const msg = e.name === 'TokenExpiredError' ? 'Session expired. Please log in again.' : 'Invalid token.';
    res.status(401).json({ error: msg });
  }
}

// ── AUTH ROUTES ───────────────────────────────────────────────────────────
app.post('/api/auth/register', rateLimit(15 * 60 * 1000, 5), async (req, res) => {
  try {
    const { username, email, password, recaptchaToken } = req.body;

    // ── Input validation
    if (!username || !email || !password)
      return res.status(400).json({ error: 'All fields are required.' });
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username))
      return res.status(400).json({ error: 'Username: 3–30 chars, letters/numbers/underscore only.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });

    // ── reCAPTCHA
    if (!recaptchaToken)
      return res.status(400).json({ error: 'Complete the reCAPTCHA check.' });
    if (!await verifyRecaptcha(recaptchaToken))
      return res.status(400).json({ error: 'reCAPTCHA failed — please try again.' });

    const db = readDB();
    if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
      return res.status(409).json({ error: 'Username already taken.' });
    if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
      return res.status(409).json({ error: 'Email already registered.' });

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const user = {
      id: `u_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      username, email: email.toLowerCase(), passwordHash,
      createdAt: new Date().toISOString()
    };
    db.users.push(user);
    db.userData[user.id] = { todos: [], reminders: [], progress: {}, notes: '' };
    writeDB(db);

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: user.id, username: user.username, email: user.email, createdAt: user.createdAt } });
  } catch(e) {
    console.error('[Register]', e);
    res.status(500).json({ error: 'Registration failed — try again.' });
  }
});

app.post('/api/auth/login', rateLimit(15 * 60 * 1000, 10), async (req, res) => {
  try {
    const { username, password, recaptchaToken } = req.body;

    if (!username || !password)
      return res.status(400).json({ error: 'Username and password required.' });
    if (!recaptchaToken)
      return res.status(400).json({ error: 'Complete the reCAPTCHA check.' });
    if (!await verifyRecaptcha(recaptchaToken))
      return res.status(400).json({ error: 'reCAPTCHA failed — please try again.' });

    const db   = readDB();
    const user = db.users.find(u =>
      u.username.toLowerCase() === username.toLowerCase() ||
      u.email.toLowerCase()    === username.toLowerCase()
    );
    if (!user || !await bcrypt.compare(password, user.passwordHash))
      return res.status(401).json({ error: 'Invalid username or password.' });

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, createdAt: user.createdAt } });
  } catch(e) {
    console.error('[Login]', e);
    res.status(500).json({ error: 'Login failed — try again.' });
  }
});

app.get('/api/auth/me', auth, (req, res) => {
  const u = readDB().users.find(u => u.id === req.userId);
  if (!u) return res.status(404).json({ error: 'User not found.' });
  res.json({ id: u.id, username: u.username, email: u.email, createdAt: u.createdAt });
});

// ── Change password ───────────────────────────────────────────────────────
app.post('/api/auth/change-password', auth, rateLimit(60 * 60 * 1000, 5), async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword)
      return res.status(400).json({ error: 'Both passwords required.' });
    if (newPassword.length < 6)
      return res.status(400).json({ error: 'New password must be 6+ chars.' });
    const db = readDB();
    const i  = db.users.findIndex(u => u.id === req.userId);
    if (i === -1) return res.status(404).json({ error: 'User not found.' });
    if (!await bcrypt.compare(oldPassword, db.users[i].passwordHash))
      return res.status(401).json({ error: 'Current password is wrong.' });
    db.users[i].passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    writeDB(db);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Could not change password.' }); }
});

// ── TODOS (per-user) ──────────────────────────────────────────────────────
app.get   ('/api/todos',     auth, (req, res) => {
  const db = readDB(); res.json(userSlot(db, req.userId).todos);
});
app.post  ('/api/todos',     auth, (req, res) => {
  const db = readDB(), s = userSlot(db, req.userId);
  const t = { id: Date.now(), text: req.body.text, done: false,
              priority: req.body.priority || 'medium', due: req.body.due || null,
              created: new Date().toISOString() };
  s.todos.push(t); writeDB(db); res.json(t);
});
app.put   ('/api/todos/:id', auth, (req, res) => {
  const db = readDB(), s = userSlot(db, req.userId);
  const i = s.todos.findIndex(t => t.id == req.params.id);
  if (i === -1) return res.status(404).json({ error: 'Not found.' });
  s.todos[i] = { ...s.todos[i], ...req.body }; writeDB(db); res.json(s.todos[i]);
});
app.delete('/api/todos/:id', auth, (req, res) => {
  const db = readDB(), s = userSlot(db, req.userId);
  s.todos = s.todos.filter(t => t.id != req.params.id); writeDB(db); res.json({ ok: true });
});

// ── REMINDERS (per-user) ──────────────────────────────────────────────────
app.get   ('/api/reminders',     auth, (req, res) => {
  const db = readDB(); res.json(userSlot(db, req.userId).reminders);
});
app.post  ('/api/reminders',     auth, (req, res) => {
  const db = readDB(), s = userSlot(db, req.userId);
  const r = { id: Date.now(), title: req.body.title, time: req.body.time,
              days: req.body.days || [], active: true, created: new Date().toISOString() };
  s.reminders.push(r); writeDB(db); res.json(r);
});
app.put   ('/api/reminders/:id', auth, (req, res) => {
  const db = readDB(), s = userSlot(db, req.userId);
  const i = s.reminders.findIndex(r => r.id == req.params.id);
  if (i === -1) return res.status(404).json({ error: 'Not found.' });
  s.reminders[i] = { ...s.reminders[i], ...req.body }; writeDB(db); res.json(s.reminders[i]);
});
app.delete('/api/reminders/:id', auth, (req, res) => {
  const db = readDB(), s = userSlot(db, req.userId);
  s.reminders = s.reminders.filter(r => r.id != req.params.id); writeDB(db); res.json({ ok: true });
});

// ── PROGRESS (per-user) ───────────────────────────────────────────────────
app.get ('/api/progress',      auth, (req, res) => {
  const db = readDB(); res.json(userSlot(db, req.userId).progress);
});
app.post('/api/progress',      auth, (req, res) => {
  const db = readDB(), s = userSlot(db, req.userId);
  s.progress[req.body.id] = { watched: req.body.watched, date: new Date().toISOString() };
  writeDB(db); res.json({ ok: true });
});
app.post('/api/progress/sync', auth, (req, res) => {
  const db = readDB(), s = userSlot(db, req.userId);
  Object.assign(s.progress, req.body);
  writeDB(db); res.json({ ok: true, total: Object.keys(s.progress).length });
});

// ── NOTES (per-user) ──────────────────────────────────────────────────────
app.get ('/api/notes', auth, (req, res) => {
  const db = readDB(); res.json({ notes: userSlot(db, req.userId).notes || '' });
});
app.post('/api/notes', auth, (req, res) => {
  const db = readDB(), s = userSlot(db, req.userId);
  s.notes = req.body.notes || '';
  writeDB(db); res.json({ ok: true });
});

// ── STATS (per-user) ──────────────────────────────────────────────────────
app.get('/api/stats', auth, (req, res) => {
  const db = readDB(), s = userSlot(db, req.userId);
  res.json({
    totalTodos      : s.todos.length,
    doneTodos       : s.todos.filter(t => t.done).length,
    totalReminders  : s.reminders.length,
    activeReminders : s.reminders.filter(r => r.active).length,
    progressItems   : Object.keys(s.progress).length,
    watchedItems    : Object.values(s.progress).filter(p => p.watched).length,
  });
});

// ── PING & HEALTH ─────────────────────────────────────────────────────────
app.get('/ping',   (_req, res) => res.json({ status: 'alive', time: new Date().toISOString(), uptime: process.uptime() }));
app.get('/health', (_req, res) => res.json({ ok: true }));

// ── ADMIN: user count (no sensitive data) ────────────────────────────────
app.get('/api/admin/count', (req, res) => {
  const db = readDB();
  res.json({ users: db.users.length });
});

// ── Self-ping ─────────────────────────────────────────────────────────────
function selfPing() {
  const url = APP_URL + '/ping';
  (url.startsWith('https') ? https : http)
    .get(url, r => console.log(`[KeepAlive] ${new Date().toLocaleTimeString()} — ${r.statusCode}`))
    .on('error', e => console.log(`[KeepAlive] failed: ${e.message}`));
}
setTimeout(() => { selfPing(); setInterval(selfPing, 10 * 60 * 1000); }, 30_000);

// ── START ─────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅  Server running on port ${PORT}`);
  console.log(`🔗  ${APP_URL}`);
  console.log(`🔑  JWT_SECRET : ${JWT_SECRET.includes('CHANGE') ? '⚠️  DEFAULT — set env var!' : '✅ custom'}`);
  console.log(`🤖  reCAPTCHA  : ${RECAPTCHA_SECRET ? '✅ configured' : '⚠️  not set (dev bypass on)'}`);
});
