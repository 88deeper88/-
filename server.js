const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory user store (replace with a database in production)
const users = {};

// Session activity log — each entry: { username, timestamp (ms) }
const sessionLog = [];

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 }
}));

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  if (req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  if (username.length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  if (users[username]) {
    return res.status(409).json({ error: 'Username already taken.' });
  }

  const hash = await bcrypt.hash(password, 12);
  users[username] = { username, password: hash };
  req.session.userId = username;
  sessionLog.push({ username, timestamp: Date.now() });
  res.json({ success: true });
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const user = users[username];
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  req.session.userId = username;
  sessionLog.push({ username, timestamp: Date.now() });
  res.json({ success: true });
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.session.userId });
});

app.get('/report', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'report.html'));
});

app.get('/api/report/30day', requireAuth, (req, res) => {
  const now = Date.now();
  const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;

  const recent = sessionLog.filter((e) => e.timestamp >= thirtyDaysAgo);

  // Build a map: YYYY-MM-DD -> { logins, users: Set }
  const byDay = {};
  for (let i = 29; i >= 0; i--) {
    const d = new Date(now - i * 24 * 60 * 60 * 1000);
    const key = d.toISOString().slice(0, 10);
    byDay[key] = { date: key, logins: 0, uniqueUsers: new Set() };
  }

  for (const entry of recent) {
    const key = new Date(entry.timestamp).toISOString().slice(0, 10);
    if (byDay[key]) {
      byDay[key].logins += 1;
      byDay[key].uniqueUsers.add(entry.username);
    }
  }

  const days = Object.values(byDay).map((d) => ({
    date: d.date,
    logins: d.logins,
    uniqueUsers: d.uniqueUsers.size,
  }));

  const totalLogins = recent.length;
  const uniqueUsers = new Set(recent.map((e) => e.username)).size;
  const peakDay = days.reduce((a, b) => (b.logins > a.logins ? b : a), days[0]);

  res.json({ days, totalLogins, uniqueUsers, peakDay });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
