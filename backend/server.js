/**
 * ByteChief AI — Backend Server (Render-ready)
 * Node.js + Express + MongoDB Atlas + Groq AI
 * Author: Obasanjo Samuel — Tribal Chief Tech
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const path = require('path');
const Groq = require('groq-sdk');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'bytechief-dev-secret-change-in-prod';
const GROQ_KEY = process.env.GROQ_API_KEY;
const MONGO_URI = process.env.MONGO_URI;
const ADMIN_USER = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'changeme-in-env';

// ── TRUST PROXY ────────────────────────────────────────────────────────────────
app.set('trust proxy', 1);

// ── Groq ───────────────────────────────────────────────────────────────────────
const groq = GROQ_KEY ? new Groq({ apiKey: GROQ_KEY }) : null;

// ── MongoDB ────────────────────────────────────────────────────────────────────
if (MONGO_URI) {
  mongoose.connect(MONGO_URI)
    .then(async () => {
      console.log('✅ MongoDB connected');
      await seedAdmin();
    })
    .catch(err => console.error('❌ MongoDB:', err.message));
} else {
  console.warn('⚠️ No MONGO_URI — using in-memory storage');
}

// ── Schemas ────────────────────────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  email:      { type: String, required: true, unique: true, lowercase: true, trim: true },
  name:       { type: String, default: '' },
  password:   { type: String },
  provider:   { type: String, default: 'email' },
  role:       { type: String, default: 'user' },
  lastActive: { type: Date, default: Date.now },
}, { timestamps: true });

const LogSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  userEmail: String,
  userName:  String,
  command:   { type: String, required: true },
  response:  { type: String, required: true },
  model:     { type: String, default: 'groq' },
}, { timestamps: true });

const User    = mongoose.models.BCUser || mongoose.model('BCUser', UserSchema);
const ChatLog = mongoose.models.BCLog  || mongoose.model('BCLog', LogSchema);

// ── In-memory fallback ─────────────────────────────────────────────────────────
const memUsers = [];
const memLogs  = [];
let   memIdSeq = 1;

// ── Seed admin ─────────────────────────────────────────────────────────────────
async function seedAdmin() {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || `${ADMIN_USER}@bytechief.ai`;
    const existing = await User.findOne({ email: adminEmail });
    if (!existing) {
      await User.create({
        email:    adminEmail,
        name:     'ByteChief Admin',
        password: await bcrypt.hash(ADMIN_PASS, 10),
        role:     'admin',
      });
      console.log(`✅ Admin seeded → ${adminEmail}`);
    }
  } catch (e) { console.warn('Admin seed skipped:', e.message); }
}

// ── Core middleware ────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..')));

// ── Rate limiters ──────────────────────────────────────────────────────────────
const apiLimiter = rateLimit({ windowMs: 15*60*1000, max: 150, message: { error: 'Too many requests' } });
const chatLimit  = rateLimit({ windowMs:  1*60*1000, max:  25, message: { error: 'Slow down — too many messages' } });
app.use('/api/', apiLimiter);

// ── Auth middleware ────────────────────────────────────────────────────────────
const authMw = (req, res, next) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token required' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
};

const adminMw = (req, res, next) =>
  req.user?.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' });

// ── Helper: make JWT ───────────────────────────────────────────────────────────
function makeToken(user) {
  return jwt.sign(
    { id: user._id || user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { email, name, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    if (MONGO_URI) {
      const existing = await User.findOne({ email });
      if (existing) return res.status(409).json({ error: 'Email already registered' });
      const hashed = await bcrypt.hash(password, 10);
      const user   = await User.create({ email, name: name || '', password: hashed });
      return res.json({ token: makeToken(user), user: { id: user._id, email: user.email, name: user.name, role: user.role } });
    } else {
      if (memUsers.find(u => u.email === email.toLowerCase())) return res.status(409).json({ error: 'Email already registered' });
      const hashed = await bcrypt.hash(password, 10);
      const user   = { id: memIdSeq++, email: email.toLowerCase(), name: name || '', password: hashed, role: 'user', createdAt: new Date() };
      memUsers.push(user);
      return res.json({ token: makeToken(user), user: { id: user.id, email: user.email, name: user.name, role: user.role } });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    let user;
    if (MONGO_URI) {
      user = await User.findOne({ email: email.toLowerCase() });
    } else {
      user = memUsers.find(u => u.email === email.toLowerCase());
    }

    if (!user || !user.password) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    if (MONGO_URI) {
      await User.findByIdAndUpdate(user._id, { lastActive: new Date() });
    }

    res.json({ token: makeToken(user), user: { id: user._id || user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /api/admin/login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  try {
    const adminEmail = process.env.ADMIN_EMAIL || `${ADMIN_USER}@bytechief.ai`;
    let user;
    if (MONGO_URI) {
      user = await User.findOne({ email: adminEmail, role: 'admin' });
    } else {
      user = memUsers.find(u => u.role === 'admin');
    }

    if (!user) return res.status(401).json({ error: 'Admin not found' });
    if (username !== ADMIN_USER) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    res.json({ token: makeToken(user), user: { id: user._id || user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Admin login failed' });
  }
});

// GET /api/me
app.get('/api/me', authMw, async (req, res) => {
  try {
    let user;
    if (MONGO_URI) {
      user = await User.findById(req.user.id).select('-password');
    } else {
      const u = memUsers.find(u => u.id === req.user.id);
      if (u) { const { password, ...rest } = u; user = rest; }
    }
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// AI CHAT ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/chat
app.post('/api/chat', authMw, chatLimit, async (req, res) => {
  const { message, history = [] } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });

  try {
    let reply;

    if (groq) {
      const messages = [
        { role: 'system', content: 'You are ByteChief AI, a helpful and friendly web assistant powered by Groq. Be concise, accurate, and helpful.' },
        ...history.slice(-10).map(h => ({ role: h.role, content: h.content })),
        { role: 'user', content: message },
      ];

      const completion = await groq.chat.completions.create({
        model:      'llama-3.3-70b-versatile',
        messages,
        max_tokens: 1024,
        temperature: 0.7,
      });

      reply = completion.choices[0]?.message?.content || 'No response generated.';
    } else {
      reply = `[Mock mode — no GROQ_API_KEY] You said: "${message}"`;
    }

    // Save log
    const logData = {
      userId:    req.user.id,
      userEmail: req.user.email,
      userName:  req.user.name,
      command:   message,
      response:  reply,
      model:     groq ? 'groq-llama-3.3-70b' : 'mock',
    };
    if (MONGO_URI) {
      await ChatLog.create(logData);
      await User.findByIdAndUpdate(req.user.id, { lastActive: new Date() });
    } else {
      memLogs.push({ ...logData, id: memIdSeq++, createdAt: new Date() });
    }

    res.json({ reply });
  } catch (e) {
    console.error('Chat error:', e);
    res.status(500).json({ error: 'AI request failed. Please try again.' });
  }
});

// GET /api/history  — user's own chat history
app.get('/api/history', authMw, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    let logs;
    if (MONGO_URI) {
      logs = await ChatLog.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(limit).lean();
    } else {
      logs = memLogs.filter(l => l.userId === req.user.id).slice(-limit).reverse();
    }
    res.json({ logs });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/admin/stats
app.get('/api/admin/stats', authMw, adminMw, async (req, res) => {
  try {
    let totalUsers, totalLogs, recentUsers;
    if (MONGO_URI) {
      [totalUsers, totalLogs, recentUsers] = await Promise.all([
        User.countDocuments(),
        ChatLog.countDocuments(),
        User.find().sort({ createdAt: -1 }).limit(5).select('-password').lean(),
      ]);
    } else {
      totalUsers  = memUsers.length;
      totalLogs   = memLogs.length;
      recentUsers = memUsers.slice(-5).map(({ password, ...u }) => u);
    }
    res.json({ totalUsers, totalLogs, recentUsers });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// GET /api/admin/users
app.get('/api/admin/users', authMw, adminMw, async (req, res) => {
  try {
    const page  = parseInt(req.query.page)  || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    let users, total;
    if (MONGO_URI) {
      [users, total] = await Promise.all([
        User.find().sort({ createdAt: -1 }).skip((page-1)*limit).limit(limit).select('-password').lean(),
        User.countDocuments(),
      ]);
    } else {
      total = memUsers.length;
      users = memUsers.slice((page-1)*limit, page*limit).map(({ password, ...u }) => u);
    }
    res.json({ users, total, page, pages: Math.ceil(total / limit) });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// DELETE /api/admin/users/:id
app.delete('/api/admin/users/:id', authMw, adminMw, async (req, res) => {
  try {
    if (MONGO_URI) {
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: 'User not found' });
      if (user.role === 'admin') return res.status(403).json({ error: 'Cannot delete admin' });
      await User.findByIdAndDelete(req.params.id);
      await ChatLog.deleteMany({ userId: req.params.id });
    } else {
      const idx = memUsers.findIndex(u => String(u.id) === req.params.id);
      if (idx === -1) return res.status(404).json({ error: 'User not found' });
      if (memUsers[idx].role === 'admin') return res.status(403).json({ error: 'Cannot delete admin' });
      memUsers.splice(idx, 1);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// GET /api/admin/logs
app.get('/api/admin/logs', authMw, adminMw, async (req, res) => {
  try {
    const page  = parseInt(req.query.page)  || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    let logs, total;
    if (MONGO_URI) {
      [logs, total] = await Promise.all([
        ChatLog.find().sort({ createdAt: -1 }).skip((page-1)*limit).limit(limit).lean(),
        ChatLog.countDocuments(),
      ]);
    } else {
      total = memLogs.length;
      logs  = memLogs.slice((page-1)*limit, page*limit).reverse();
    }
    res.json({ logs, total, page, pages: Math.ceil(total / limit) });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// HEALTH CHECK
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/health', (req, res) => {
  res.json({
    status:   'ok',
    ai:       groq     ? 'groq-connected'  : 'mock-mode',
    database: MONGO_URI ? 'mongodb-atlas'  : 'in-memory',
    uptime:   Math.floor(process.uptime()),
    version:  '1.0.0',
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// 404 FALLBACK
// ══════════════════════════════════════════════════════════════════════════════

app.use('/api/', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// ── Start server ───────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n⚡ ByteChief AI Server`);
  console.log(`🌐  http://localhost:${PORT}`);
  console.log(`🤖  AI: ${groq ? 'Groq connected' : 'Mock mode (no GROQ_API_KEY)'}`);
  console.log(`🗄️   DB: ${MONGO_URI ? 'MongoDB Atlas' : 'In-memory (no MONGO_URI)'}\n`);
});