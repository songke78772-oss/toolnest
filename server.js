require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const { LemonSqueezy } = require('@lemonsqueezy/lemonsqueezy.js');

const app = express();
const ls = new LemonSqueezy(process.env.LEMONSQUEEZY_API_KEY);

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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    filename TEXT NOT NULL,
    version TEXT DEFAULT '1.0',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + '-' + file.originalname);
  }
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

function requireSubscription(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.subscription_status !== 'active') {
    return res.redirect('/dashboard?need_sub=1');
  }
  req.user = user;
  next();
}

// Home
app.get('/', (req, res) => {
  const toolsCount = db.prepare('SELECT COUNT(*) as c FROM tools').get().c;
  res.render('index', { 
    loggedIn: !!req.session.userId,
    toolsCount,
    price: '1.99'
  });
});

// Register
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

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
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.render('register', { error: 'Email already registered' });
    }
    res.render('register', { error: 'Registration failed' });
  }
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.render('login', { error: 'Invalid email or password' });
  }
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Dashboard
app.get('/dashboard', requireLogin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  const tools = db.prepare('SELECT * FROM tools ORDER BY updated_at DESC').all();
  res.render('dashboard', { 
    user, 
    tools, 
    needSub: req.query.need_sub,
    publishableKey: '',
    priceId: ''
  });
});

// Create Lemon Squeezy Checkout
app.post('/create-checkout-session', requireLogin, async (req, res) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    const checkout = await ls.checkouts.create({
      storeId: process.env.LEMONSQUEEZY_STORE_ID,
      variantId: process.env.LEMONSQUEEZY_VARIANT_ID,
      checkoutData: {
        email: user.email,
        custom: { user_id: user.id.toString() }
      },
      checkoutOptions: {
        embed: false,
        media: false,
        logo: true
      },
      productOptions: {
        redirectUrl: `${process.env.APP_URL}/success`,
        receiptButtonText: 'Go to Dashboard',
        receiptThankYouNote: 'Thanks for subscribing!'
      }
    });

    res.json({ url: checkout.data.attributes.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Success
app.get('/success', requireLogin, (req, res) => {
  res.render('success');
});

// Download (protected)
app.get('/download/:id', requireSubscription, (req, res) => {
  const tool = db.prepare('SELECT * FROM tools WHERE id = ?').get(req.params.id);
  if (!tool) return res.status(404).send('Tool not found');
  const filePath = path.join(__dirname, 'uploads', tool.filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('File missing');
  res.download(filePath, tool.name.replace(/\s+/g, '-') + '-' + tool.version + path.extname(tool.filename));
});

// Lemon Squeezy Webhook
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.headers['x-signature'];
  const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET || '';

  const hmac = crypto.createHmac('sha256', secret);
  const digest = Buffer.from(hmac.update(req.body).digest('hex'), 'utf8');
  const signatureBuffer = Buffer.from(signature || '', 'utf8');

  if (secret && !crypto.timingSafeEqual(digest, signatureBuffer)) {
    return res.status(401).send('Invalid signature');
  }

  const event = JSON.parse(req.body.toString());

  if (event.meta.event_name === 'subscription_created' || event.meta.event_name === 'subscription_updated') {
    const sub = event.data.attributes;
    const userId = event.meta.custom_data?.user_id;
    if (userId) {
      const status = sub.status === 'active' ? 'active' : 'inactive';
      db.prepare('UPDATE users SET subscription_status = ?, subscription_id = ? WHERE id = ?')
        .run(status, event.data.id, userId);
    }
  }

  if (event.meta.event_name === 'subscription_cancelled' || event.meta.event_name === 'subscription_expired') {
    const userId = event.meta.custom_data?.user_id;
    if (userId) {
      db.prepare('UPDATE users SET subscription_status = ? WHERE id = ?').run('inactive', userId);
    }
  }

  res.json({ received: true });
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

app.post('/admin/upload', upload.single('file'), (req, res) => {
  if (!req.session.isAdmin) return res.status(403).send('Forbidden');
  const { name, description, version } = req.body;
  if (!req.file || !name) return res.redirect('/admin/dashboard?error=missing');
  db.prepare('INSERT INTO tools (name, description, filename, version) VALUES (?, ?, ?, ?)')
    .run(name, description || '', req.file.filename, version || '1.0');
  res.redirect('/admin/dashboard');
});

app.post('/admin/delete/:id', (req, res) => {
  if (!req.session.isAdmin) return res.status(403).send('Forbidden');
  const tool = db.prepare('SELECT * FROM tools WHERE id = ?').get(req.params.id);
  if (tool) {
    const filePath = path.join(__dirname, 'uploads', tool.filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    db.prepare('DELETE FROM tools WHERE id = ?').run(req.params.id);
  }
  res.redirect('/admin/dashboard');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Office Tools Pro running on port ${PORT}`);
  console.log(`Local: http://localhost:${PORT}`);
});
