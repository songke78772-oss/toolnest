require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const { Resend } = require('resend');
const multer = require('multer');
const FormData = require('form-data');
const fs = require('fs');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const app = express();
const db = new Database(path.join(__dirname, 'data', 'app.db'));
const resend = new Resend(process.env.RESEND_API_KEY);
const upload = multer({ dest: 'uploads/' });

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
    usage_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

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

function requireValidSession(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  const user = db.prepare('SELECT session_token FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.session_token !== req.session.sessionToken) {
    req.session.destroy();
    return res.redirect('/login?error=session_expired');
  }
  next();
}

app.get('/', (req, res) => {
  const q = req.query.q || '';
  const cat = req.query.cat || '';
  let tools = db.prepare('SELECT * FROM tools ORDER BY id DESC').all();

  if (q) {
    const lower = q.toLowerCase();
    tools = tools.filter(t => 
      t.name.toLowerCase().includes(lower) || 
      (t.description || '').toLowerCase().includes(lower)
    );
  }
  if (cat) tools = tools.filter(t => t.category === cat);

  const categories = [...new Set(db.prepare('SELECT DISTINCT category FROM tools').all().map(t => t.category))];

  res.render('index', { 
    tools, 
    loggedIn: !!req.session.userId,
    price: '1.99',
    q,
    cat,
    categories
  });
});

app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { email, password, confirmPassword } = req.body;
  if (!email || !password) return res.render('register', { error: 'All fields required' });
  if (password !== confirmPassword) return res.render('register', { error: 'Passwords do not match' });
  if (password.length < 6) return res.render('register', { error: 'Password must be at least 6 characters' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.render('register', { error: 'Email already registered' });

  const hash = await bcrypt.hash(password, 10);
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  db.prepare('INSERT INTO users (email, password_hash, verification_code) VALUES (?, ?, ?)').run(email, hash, code);

  try {
    await resend.emails.send({
      from: 'ToolNest <onboarding@resend.dev>',
      to: email,
      subject: 'Your ToolNest Verification Code',
      html: `<p>Your verification code is: <strong>${code}</strong></p><p>This code expires in 10 minutes.</p>`
    });
  } catch (err) {
    console.error('Email error:', err);
  }

  res.render('verify', { email, error: null });
});

app.get('/verify', (req, res) => {
  res.render('verify', { email: req.query.email || '', error: null });
});

app.post('/verify', (req, res) => {
  const { email, code } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  
  if (!user || String(user.verification_code).trim() !== String(code).trim()) {
    return res.render('verify', { email, error: 'Invalid verification code' });
  }
  
  db.prepare('UPDATE users SET verified = 1, verification_code = NULL WHERE id = ?').run(user.id);
  res.redirect('/login?verified=1');
});

app.get('/login', (req, res) => {
  const error = req.query.error === 'session_expired' ? 'You have been logged out from another device' : null;
  res.render('login', { error, verified: req.query.verified });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.render('login', { error: 'Invalid email or password' });
  }
  if (!user.verified) {
    return res.render('login', { error: 'Please verify your email first' });
  }
  const sessionToken = crypto.randomBytes(32).toString('hex');
  db.prepare('UPDATE users SET session_token = ? WHERE id = ?').run(sessionToken, user.id);
  req.session.userId = user.id;
  req.session.sessionToken = sessionToken;
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/dashboard', requireValidSession, (req, res) => {
  const user = db.prepare('SELECT email FROM users WHERE id = ?').get(req.session.userId);
  const favorites = [];
  const usage = [];
  res.render('dashboard', { user, favorites, usage });
});

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
  const users = db.prepare('SELECT id, email, verified, created_at FROM users ORDER BY id DESC').all();
  res.render('admin', { tools, users });
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

app.post('/admin/delete-user/:id', (req, res) => {
  if (!req.session.isAdmin) return res.redirect('/admin');
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.redirect('/admin/dashboard');
});

app.get('/admin/logout', (req, res) => {
  req.session.isAdmin = false;
  res.redirect('/admin');
});

// 工具跳转（需要登录）
app.get('/tool/:id', requireValidSession, (req, res) => {
  const tool = db.prepare('SELECT * FROM tools WHERE id = ?').get(req.params.id);
  if (!tool || !tool.url) {
    return res.status(404).send('Tool not found');
  }
  db.prepare('UPDATE tools SET usage_count = COALESCE(usage_count, 0) + 1 WHERE id = ?').run(tool.id);
  res.redirect(tool.url);
});

// PDF 转换页面
app.get('/pdf-converter', requireValidSession, (req, res) => {
  res.render('pdf-converter');
});

// AI PPT 工具（二次封装）
app.get('/ppt', requireLogin, (req, res) => {
  res.render('ppt');
});

// 转换 API
app.post('/api/convert-to-pdf', requireValidSession, upload.single('file'), async (req, res) => {
  if (!req.file) return res.json({ success: false, error: 'No file' });

  try {
    const form = new FormData();
    form.append('files', fs.createReadStream(req.file.path), req.file.originalname);

    const response = await fetch('http://127.0.0.1:3001/forms/libreoffice/convert', {
      method: 'POST',
      body: form,
      headers: form.getHeaders()
    });

    if (!response.ok) throw new Error('Gotenberg error');

    const outDir = path.join(__dirname, 'public', 'converted');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

    const filename = Date.now() + '.pdf';
    const outPath = path.join(outDir, filename);
    const buffer = Buffer.from(await response.arrayBuffer());
    fs.writeFileSync(outPath, buffer);

    fs.unlinkSync(req.file.path);

    res.json({ success: true, url: '/converted/' + filename });
  } catch (err) {
    console.error(err);
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.json({ success: false, error: 'Conversion failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ToolNest running on port ${PORT}`);
});
