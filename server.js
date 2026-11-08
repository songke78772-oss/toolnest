require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');

const app = express();

// Database
const db = new Database(path.join(__dirname, 'data', 'app.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    stripe_customer_id TEXT,
    subscription_status TEXT DEFAULT 'inactive',
    subscription_id TEXT,
    subscription_end DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT DEFAULT 'office',
    url TEXT NOT NULL,
    icon TEXT DEFAULT '🔧',
    usage_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    tool_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, tool_id)
  );

  CREATE TABLE IF NOT EXISTS tool_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    request TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    reply TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS usage_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    tool_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

async function sendEmail(to, subject, html) {
  if (!process.env.SMTP_USER) return console.log('Email skipped (no SMTP config)');
  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to,
      subject,
      html
    });
  } catch (err) {
    console.error('Email error:', err.message);
  }
}

// Session & middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'toolnest-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

// Categories
const CATEGORIES = [
  { id: 'office', name: 'Office', icon: '💼' },
  { id: 'life', name: 'Life', icon: '🏠' },
  { id: 'entertainment', name: 'Entertainment', icon: '🎮' },
  { id: 'dev', name: 'Development', icon: '💻' },
  { id: 'design', name: 'Design', icon: '🎨' },
  { id: 'other', name: 'Other', icon: '📦' }
];

// Routes
app.get('/', (req, res) => {
  const q = req.query.q || '';
  const cat = req.query.cat || '';
  let sql = 'SELECT * FROM tools WHERE 1=1';
  const params = [];
  if (q) { sql += ' AND (name LIKE ? OR description LIKE ?)'; params.push(`%${q}%`, `%${q}%`); }
  if (cat) { sql += ' AND category = ?'; params.push(cat); }
  sql += ' ORDER BY usage_count DESC';
  const tools = db.prepare(sql).all(...params);
  res.render('index', { 
    loggedIn: !!req.session.userId,
    tools, categories: CATEGORIES, q, cat,
    price: '1.99'
  });
});

app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 6) {
    return res.render('register', { error: 'Email and password (min 6 chars) required' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email.toLowerCase(), hash);
    req.session.userId = result.lastInsertRowid;
    res.redirect('/dashboard');
  } catch (e) {
    res.render('register', { error: e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'Email already registered' : 'Failed' });
  }
});

app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.render('login', { error: 'Invalid email or password' });
  }
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/'); });

// User dashboard
app.get('/dashboard', requireLogin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  const favorites = db.prepare(`
    SELECT t.*, f.created_at as fav_at FROM tools t
    JOIN favorites f ON t.id = f.tool_id
    WHERE f.user_id = ? ORDER BY f.created_at DESC
  `).all(req.session.userId);
  const usage = db.prepare(`
    SELECT t.name, COUNT(*) as count FROM usage_logs u
    JOIN tools t ON u.tool_id = t.id
    WHERE u.user_id = ? GROUP BY t.id ORDER BY count DESC LIMIT 10
  `).all(req.session.userId);
  res.render('dashboard', { user, favorites, usage });
});

// Favorite toggle
app.post('/favorite/:id', requireLogin, (req, res) => {
  const toolId = req.params.id;
  const exists = db.prepare('SELECT id FROM favorites WHERE user_id = ? AND tool_id = ?').get(req.session.userId, toolId);
  if (exists) {
    db.prepare('DELETE FROM favorites WHERE user_id = ? AND tool_id = ?').run(req.session.userId, toolId);
  } else {
    db.prepare('INSERT INTO favorites (user_id, tool_id) VALUES (?, ?)').run(req.session.userId, toolId);
  }
  res.redirect(req.get('Referer') || '/');
});

// Tool request
app.post('/request-tool', (req, res) => {
  const { email, request } = req.body;
  if (email && request) {
    db.prepare('INSERT INTO tool_requests (email, request) VALUES (?, ?)').run(email, request);
  }
  res.redirect('/?requested=1');
});

// Tool page (log usage)
app.get('/tool/:id', requireLogin, (req, res) => {
  const tool = db.prepare('SELECT * FROM tools WHERE id = ?').get(req.params.id);
  if (!tool) return res.redirect('/');
  db.prepare('UPDATE tools SET usage_count = usage_count + 1 WHERE id = ?').run(tool.id);
  db.prepare('INSERT INTO usage_logs (user_id, tool_id) VALUES (?, ?)').run(req.session.userId, tool.id);
  res.redirect(tool.url);
});

// Admin
app.get('/admin', (req, res) => {
  if (req.session.isAdmin) return res.redirect('/admin/dashboard');
  res.render('admin-login', { error: null });
});

app.post('/admin/login', (req, res) => {
  if (req.body.password === process.env.ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    return res.redirect('/admin/dashboard');
  }
  res.render('admin-login', { error: 'Wrong password' });
});

app.get('/admin/dashboard', (req, res) => {
  if (!req.session.isAdmin) return res.redirect('/admin');
  const tools = db.prepare('SELECT * FROM tools ORDER BY id DESC').all();
  const requests = db.prepare('SELECT * FROM tool_requests ORDER BY id DESC').all();
  res.render('admin', { tools, requests, categories: CATEGORIES });
});

app.post('/admin/add-tool', (req, res) => {
  if (!req.session.isAdmin) return res.status(403).send('Forbidden');
  const { name, description, category, url, icon } = req.body;
  if (name && url) {
    db.prepare('INSERT INTO tools (name, description, category, url, icon) VALUES (?, ?, ?, ?, ?)')
      .run(name, description || '', category || 'office', url, icon || '🔧');
  }
  res.redirect('/admin/dashboard');
});

app.post('/admin/delete/:id', (req, res) => {
  if (!req.session.isAdmin) return res.status(403).send('Forbidden');
  db.prepare('DELETE FROM tools WHERE id = ?').run(req.params.id);
  res.redirect('/admin/dashboard');
});

app.post('/admin/reply/:id', async (req, res) => {
  if (!req.session.isAdmin) return res.status(403).send('Forbidden');
  const { reply } = req.body;
  const request = db.prepare('SELECT * FROM tool_requests WHERE id = ?').get(req.params.id);
  if (request && reply) {
    db.prepare('UPDATE tool_requests SET status = ?, reply = ? WHERE id = ?').run('replied', reply, req.params.id);
    await sendEmail(request.email, 'Your Tool Request - ToolNest', `<p>${reply}</p>`);
  }
  res.redirect('/admin/dashboard');
});

// Email announcements (admin)
app.post('/admin/announce', async (req, res) => {
  if (!req.session.isAdmin) return res.status(403).send('Forbidden');
  const { subject, message } = req.body;
  const users = db.prepare("SELECT email FROM users WHERE subscription_status = 'active'").all();
  for (const u of users) {
    await sendEmail(u.email, subject, `<p>${message}</p>`);
  }
  res.redirect('/admin/dashboard?sent=1');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`ToolNest running on port ${PORT}`));
