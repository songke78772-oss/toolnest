require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const Database = require('better-sqlite3');
const crypto = require('crypto');

const app = express();
const db = new Database(path.join(__dirname, 'data', 'app.db'));

// 数据库表
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    verification_code TEXT,
    session_token TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    icon TEXT DEFAULT '🔧',
    url TEXT,
    category TEXT DEFAULT 'Office',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Session
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

// 中间件：检查有效会话
function requireValidSession(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  const user = db.prepare('SELECT session_token FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.session_token !== req.session.sessionToken) {
    req.session.destroy();
    return res.redirect('/login?error=session_expired');
  }
  next();
}

// 首页
app.get('/', (req, res) => {
  const tools = db.prepare('SELECT * FROM tools ORDER BY id DESC').all();
  res.render('index', { tools, user: req.session.userId });
});

// 注册页面
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// 注册处理
app.post('/register', async (req, res) => {
  const { email, password, confirmPassword } = req.body;

  if (!email || !password) return res.render('register', { error: 'All fields required' });
  if (password !== confirmPassword) return res.render('register', { error: 'Passwords do not match' });
  if (password.length < 6) return res.render('register', { error: 'Password must be at least 6 characters' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.render('register', { error: 'Email already registered' });

  const hash = await bcrypt.hash(password, 10);
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const result = db.prepare('INSERT INTO users (email, password_hash, verification_code) VALUES (?, ?, ?)').run(email, hash, code);

  // TODO: 用 Resend 发送验证邮件
  console.log(`Verification code for ${email}: ${code}`);

  res.render('verify', { email, error: null });
});

// 验证页面
app.get('/verify', (req, res) => {
  res.render('verify', { email: req.query.email || '', error: null });
});

// 验证处理
app.post('/verify', (req, res) => {
  const { email, code } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user || user.verification_code !== code) {
    return res.render('verify', { email, error: 'Invalid verification code' });
  }

  db.prepare('UPDATE users SET verified = 1, verification_code = NULL WHERE id = ?').run(user.id);
  res.redirect('/login?verified=1');
});

// 登录页面
app.get('/login', (req, res) => {
  const error = req.query.error === 'session_expired' ? 'You have been logged out from another device' : null;
  res.render('login', { error, verified: req.query.verified });
});

// 登录处理
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.render('login', { error: 'Invalid email or password' });
  }

  if (!user.verified) {
    return res.render('login', { error: 'Please verify your email first' });
  }

  // 生成新 session token，踢掉旧会话
  const sessionToken = crypto.randomBytes(32).toString('hex');
  db.prepare('UPDATE users SET session_token = ? WHERE id = ?').run(sessionToken, user.id);

  req.session.userId = user.id;
  req.session.sessionToken = sessionToken;
  res.redirect('/dashboard');
});

// 登出
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 仪表盘
app.get('/dashboard', requireValidSession, (req, res) => {
  const user = db.prepare('SELECT email FROM users WHERE id = ?').get(req.session.userId);
  res.render('dashboard', { user });
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
  res.render('admin', { tools });
});

app.post('/admin/add-tool', (req, res) => {
  if (!req.session.isAdmin) return res.redirect('/admin');
  const { name, description, icon, url, category } = req.body;
  db.prepare('INSERT INTO tools (name, description, icon, url, category) VALUES (?, ?, ?, ?, ?)').run(name, description, icon || '🔧', url, category || 'Office');
  res.redirect('/admin/dashboard');
});

app.post('/admin/delete/:id', (req, res) => {
  if (!req.session.isAdmin) return res.redirect('/admin');
  db.prepare('DELETE FROM tools WHERE id = ?').run(req.params.id);
  res.redirect('/admin/dashboard');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ToolNest running on port ${PORT}`);
});
