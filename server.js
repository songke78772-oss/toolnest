require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const app = express();

// Database
const dbPath = path.join(__dirname, 'data', 'app.db');
if (!fs.existsSync(path.dirname(dbPath))) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
}
const db = new Database(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    stripe_customer_id TEXT,
    subscription_status TEXT DEFAULT 'inactive',
    subscription_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT DEFAULT 'Office',
    type TEXT DEFAULT 'online',
    url TEXT,
    icon TEXT DEFAULT '🔧',
    filename TEXT,
    version TEXT DEFAULT '1.0',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || 'toolnest-secret-key-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

// ========== Routes ==========

// Home
app.get('/', (req, res) => {
  const q = req.query.q || '';
  const cat = req.query.cat || '';

  let sql = 'SELECT * FROM tools';
  const params = [];
  const conditions = [];

  if (q) {
    conditions.push('(name LIKE ? OR description LIKE ?)');
    params.push(`%${q}%`, `%${q}%`);
  }
  if (cat) {
    conditions.push('category = ?');
    params.push(cat);
  }
  if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
  sql += ' ORDER BY id DESC';

  const tools = db.prepare(sql).all(...params);
  const categories = db.prepare("SELECT DISTINCT category FROM tools WHERE category IS NOT NULL AND category != ''").all().map(r => r.category);

  res.render('index', {
    tools,
    loggedIn: !!req.session.userId,
    user: req.session.user || null,
    price: '1.99',
    q,
    cat,
    categories
  });
});

// Auth
app.get('/login', (req, res) => res.render('login', { error: null }));
app.get('/register', (req, res) => res.render('register', { error: null }));

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.render('register', { error: 'All fields required' });
  const hash = await bcrypt.hash(password, 10);
  try {
    db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, hash);
    res.redirect('/login');
  } catch {
    res.render('register', { error: 'Email already exists' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.render('login', { error: 'Invalid email or password' });
  }
  req.session.userId = user.id;
  req.session.user = { id: user.id, email: user.email };
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Admin
app.get('/admin', (req, res) => {
  if (req.session.isAdmin) return res.redirect('/admin/dashboard');
  res.render('admin-login', { error: null });
});

app.post('/admin/login', (req, res) => {
  if (req.body.password === (process.env.ADMIN_PASSWORD || 'admin123')) {
    req.session.isAdmin = true;
    return res.redirect('/admin/dashboard');
  }
  res.render('admin-login', { error: 'Wrong password' });
});

app.get('/admin/dashboard', (req, res) => {
  if (!req.session.isAdmin) return res.redirect('/admin');
  const tools = db.prepare('SELECT * FROM tools ORDER BY id DESC').all();
  res.render('admin', { tools });
});

app.post('/admin/add-tool', (req, res) => {
  if (!req.session.isAdmin) return res.redirect('/admin');
  const { name, description, category, type, url, icon } = req.body;
  if (!name) return res.redirect('/admin/dashboard');
  db.prepare(`
    INSERT INTO tools (name, description, category, type, url, icon)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(name, description || '', category || 'Office', type || 'online', url || '', icon || '🔧');
  res.redirect('/admin/dashboard');
});

app.post('/admin/delete/:id', (req, res) => {
  if (!req.session.isAdmin) return res.redirect('/admin');
  db.prepare('DELETE FROM tools WHERE id = ?').run(req.params.id);
  res.redirect('/admin/dashboard');
});

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ToolNest running on port ${PORT}`);
});
