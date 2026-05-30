/**
 * ByteChief AI — Backend Server v3.0 (Claude-Powered)
 * Node.js + Express + MongoDB Atlas + Anthropic Claude claude-sonnet-4
 * Author: Obasanjo Samuel — Tribal Chief Tech
 */

const express   = require('express');
const cors      = require('cors');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const mongoose  = require('mongoose');
const path      = require('path');
require('dotenv').config();

const app        = express();
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'bytechief-dev-secret-change-in-prod';
const MONGO_URI  = process.env.MONGO_URI;
const ADMIN_USER = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'ByteChief2026@@';
const ADMIN_EMAIL_ENV = process.env.ADMIN_EMAIL || 'admin@bytechief.ai';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

app.set('trust proxy', 1);

// ── MongoDB ──────────────────────────────────────────────────────────────────
if (MONGO_URI) {
  mongoose.connect(MONGO_URI)
    .then(async () => { console.log('✅ MongoDB connected'); await seedAdmin(); })
    .catch(err => console.error('❌ MongoDB:', err.message));
} else {
  console.warn('⚠️  No MONGO_URI — using in-memory storage');
}

// ── Schemas ──────────────────────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  email:      { type: String, required: true, unique: true, lowercase: true, trim: true },
  name:       { type: String, default: '' },
  password:   { type: String },
  role:       { type: String, default: 'user' },
  isInvited:  { type: Boolean, default: false },
  inviteCode: { type: String, default: '' },
  lastActive: { type: Date, default: Date.now },
  totalMessages: { type: Number, default: 0 },
  memory: {
    contacts:    { type: Object, default: {} },
    preferences: { type: Object, default: {} },
    facts:       [{ type: String }],
  },
}, { timestamps: true });

const InviteSchema = new mongoose.Schema({
  code:      { type: String, required: true, unique: true },
  email:     { type: String, default: '' },
  used:      { type: Boolean, default: false },
  usedBy:    { type: String, default: '' },
  createdBy: { type: String, default: 'admin' },
}, { timestamps: true });

const LogSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'BCUser' },
  userEmail: String,
  userName:  String,
  command:   { type: String, required: true },
  response:  { type: String, required: true },
  type:      { type: String, default: 'chat' },
  model:     { type: String, default: 'claude-sonnet-4' },
  tokens:    { type: Number, default: 0 },
}, { timestamps: true });

const User    = mongoose.models.BCUser   || mongoose.model('BCUser',   UserSchema);
const Invite  = mongoose.models.BCInvite || mongoose.model('BCInvite', InviteSchema);
const ChatLog = mongoose.models.BCLog    || mongoose.model('BCLog',    LogSchema);

// ── In-memory fallback ───────────────────────────────────────────────────────
const memUsers = [], memInvites = [], memLogs = [];
let memIdSeq = 1;

// ── Seed admin ───────────────────────────────────────────────────────────────
async function seedAdmin() {
  try {
    const existing = await User.findOne({ email: ADMIN_EMAIL_ENV });
    if (!existing) {
      await User.create({
        email:    ADMIN_EMAIL_ENV,
        name:     'ByteChief Admin',
        password: await bcrypt.hash(ADMIN_PASS, 10),
        role:     'admin',
        isInvited: true,
      });
      console.log(`✅ Admin seeded → ${ADMIN_EMAIL_ENV}`);
    }
  } catch (e) { console.warn('Admin seed skipped:', e.message); }
}

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: ALLOWED_ORIGIN === '*' ? '*' : ALLOWED_ORIGIN,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..')));

const apiLimiter = rateLimit({ windowMs: 15*60*1000, max: 500, message: { error: 'Too many requests' } });
const chatLimit  = rateLimit({ windowMs:  1*60*1000, max:  60, keyGenerator: (req) => req.user?.id || req.ip, message: { error: 'Slow down — too many messages' } });
app.use('/api/', apiLimiter);

const authMw = (req, res, next) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token required' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
};
const adminMw = (req, res, next) =>
  req.user?.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' });

function displayName(name, email) {
  return (name && name.trim()) ? name.trim() : (email ? email.split('@')[0] : 'User');
}

function makeToken(user) {
  return jwt.sign(
    { id: user._id || user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET, { expiresIn: '7d' }
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/register', async (req, res) => {
  const { email, name, password, inviteCode } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (!inviteCode)         return res.status(400).json({ error: 'Invite code required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    if (MONGO_URI) {
      const invite = await Invite.findOne({ code: inviteCode.trim().toUpperCase(), used: false });
      if (!invite) return res.status(403).json({ error: 'Invalid or already used invite code' });
      if (invite.email && invite.email !== email.toLowerCase())
        return res.status(403).json({ error: 'This invite code is not assigned to your email' });
      const existing = await User.findOne({ email });
      if (existing) return res.status(409).json({ error: 'Email already registered' });
      const user = await User.create({
        email, name: name || '',
        password: await bcrypt.hash(password, 10),
        isInvited: true, inviteCode: inviteCode.toUpperCase(),
      });
      invite.used = true; invite.usedBy = email; await invite.save();
      return res.json({ token: makeToken(user), user: { email: user.email, name: displayName(user.name, user.email), role: user.role } });
    } else {
      const inv = memInvites.find(i => i.code === inviteCode.toUpperCase() && !i.used);
      if (!inv) return res.status(403).json({ error: 'Invalid or already used invite code' });
      if (memUsers.find(u => u.email === email.toLowerCase()))
        return res.status(409).json({ error: 'Email already registered' });
      const user = { id: memIdSeq++, email: email.toLowerCase(), name: name||'', password: await bcrypt.hash(password,10), role:'user', memory:{contacts:{},preferences:{},facts:[]}, totalMessages:0 };
      memUsers.push(user); inv.used=true;
      return res.json({ token: makeToken(user), user: { email:user.email, name:displayName(user.name, user.email), role:user.role } });
    }
  } catch (e) { res.status(500).json({ error: 'Registration failed' }); }
});

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
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    if (MONGO_URI) await User.findByIdAndUpdate(user._id, { lastActive: new Date() });
    res.json({ token: makeToken(user), user: { email: user.email, name: displayName(user.name, user.email), role: user.role } });
  } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

// ── /api/me — validate token and return current user ────────────────────────
app.get('/api/me', authMw, async (req, res) => {
  try {
    let name = req.user.name || '';
    let email = req.user.email || '';
    if (MONGO_URI && req.user.id) {
      const u = await User.findById(req.user.id).select('name email').lean();
      if (u) { name = u.name || ''; email = u.email || ''; }
    }
    res.json({ id: req.user.id, email, name: displayName(name, email), role: req.user.role });
  } catch {
    const email = req.user.email || '';
    res.json({ id: req.user.id, email, name: displayName(req.user.name, email), role: req.user.role });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// MEMORY ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/memory', authMw, async (req, res) => {
  try {
    if (MONGO_URI) {
      const u = await User.findById(req.user.id).select('name email memory');
      if (!u) return res.status(404).json({ error: 'User not found' });
      return res.json({ name: displayName(u.name, u.email), email: u.email, memory: u.memory });
    }
    const u = memUsers.find(u => u.id == req.user.id);
    res.json({ name: displayName(u?.name, u?.email||req.user.email), email: u?.email||req.user.email||'', memory: u?.memory||{} });
  } catch (e) { res.status(500).json({ error: 'Failed to fetch memory' }); }
});

app.put('/api/memory', authMw, async (req, res) => {
  const { contacts, preferences, facts, name } = req.body;
  try {
    if (MONGO_URI) {
      const upd = {};
      if (name !== undefined)        upd.name = name;
      if (contacts !== undefined)    upd['memory.contacts'] = contacts;
      if (preferences !== undefined) upd['memory.preferences'] = preferences;
      if (facts !== undefined)       upd['memory.facts'] = facts;
      await User.findByIdAndUpdate(req.user.id, upd);
    } else {
      const u = memUsers.find(u => u.id == req.user.id);
      if (u) {
        if (name !== undefined)        u.name = name;
        if (contacts !== undefined)    u.memory.contacts = contacts;
        if (preferences !== undefined) u.memory.preferences = preferences;
        if (facts !== undefined)       u.memory.facts = facts;
      }
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Failed to update memory' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// CHAT LOG ROUTE (frontend calls Claude directly, this just saves logs)
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/chat', authMw, chatLimit, async (req, res) => {
  const { message, response, type } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });
  try {
    const logData = {
      userId: req.user.id, userEmail: req.user.email, userName: req.user.name,
      command: String(message).slice(0, 2000),
      response: String(response || '').slice(0, 4000),
      type: type || 'chat',
      model: 'claude-sonnet-4-20250514',
    };
    if (MONGO_URI) {
      await ChatLog.create(logData);
      await User.findByIdAndUpdate(req.user.id, { lastActive: new Date(), $inc: { totalMessages: 1 } });
    } else {
      memLogs.push({ ...logData, id: memIdSeq++, createdAt: new Date() });
      const u = memUsers.find(u => u.id == req.user.id);
      if (u) u.totalMessages = (u.totalMessages || 0) + 1;
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Log failed' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// GROQ PROXY ROUTE (server-side key — users never see it)
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/groq', authMw, chatLimit, async (req, res) => {
  const GROQ_KEY = process.env.GROQ_API_KEY;
  if (!GROQ_KEY) return res.status(503).json({ error: 'Groq not configured on this server' });

  const { model, messages, max_tokens, temperature, stream } = req.body;
  if (!model || !messages) return res.status(400).json({ error: 'model and messages required' });

  try {
    const groqAbort = new AbortController();
    const groqTimeout = setTimeout(() => groqAbort.abort(), 25000);
    const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      signal: groqAbort.signal,
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${GROQ_KEY}`,
      },
      body: JSON.stringify({
        model,
        messages,
        max_tokens:  max_tokens  || 1024,
        temperature: temperature || 0.7,
        stream:      stream      || false,
      }),
    });

    clearTimeout(groqTimeout);
    const data = await groqRes.json();
    if (!groqRes.ok) return res.status(groqRes.status).json({ error: data?.error?.message || 'Groq error' });
    res.json(data);
  } catch (e) {
    const msg = e.name === 'AbortError' ? 'Groq request timed out' : ('Groq proxy failed: ' + e.message);
    res.status(500).json({ error: msg });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// IMAGE ROUTE (Pollinations proxy)
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/image', authMw, async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt required' });
  const imageUrl = `https://image.pollinations.ai/prompt/${encodeURIComponent(prompt.trim())}?width=768&height=512&nologo=true&enhance=true`;
  res.json({ imageUrl, prompt });
});

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USER || password !== ADMIN_PASS)
    return res.status(401).json({ error: 'Invalid admin credentials' });
  const token = jwt.sign({ role: 'admin', username }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

app.get('/api/admin/stats', authMw, adminMw, async (req, res) => {
  try {
    if (MONGO_URI) {
      const [users, logs, invites] = await Promise.all([
        User.countDocuments(),
        ChatLog.countDocuments(),
        Invite.countDocuments({ used: false }),
      ]);
      const recentLogs = await ChatLog.find().sort({ createdAt: -1 }).limit(20).lean();
      const topUsers = await User.find().sort({ totalMessages: -1 }).limit(10)
        .select('email name totalMessages lastActive').lean();
      res.json({ totalUsers: users, totalLogs: logs, totalInvites: invites, recentLogs, topUsers, model: 'claude-sonnet-4-20250514' });
    } else {
      res.json({ totalUsers: memUsers.length, totalLogs: memLogs.length, totalInvites: memInvites.filter(i=>!i.used).length,
        recentLogs: memLogs.slice(-20).reverse(), topUsers: [], model: 'claude-sonnet-4-20250514' });
    }
  } catch (e) { res.status(500).json({ error: 'Stats failed' }); }
});

app.get('/api/admin/users', authMw, adminMw, async (req, res) => {
  try {
    const users = MONGO_URI
      ? await User.find().select('-password').sort({ createdAt: -1 }).lean()
      : memUsers.map(({ password, ...u }) => u);
    res.json({ users });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/users/:id', authMw, adminMw, async (req, res) => {
  try {
    if (MONGO_URI) await User.findByIdAndDelete(req.params.id);
    else { const i = memUsers.findIndex(u => u.id == req.params.id); if (i>-1) memUsers.splice(i,1); }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/invites', authMw, adminMw, async (req, res) => {
  const { email, count = 1 } = req.body;
  const invites = [];
  try {
    for (let i = 0; i < Math.min(count, 20); i++) {
      const code = Math.random().toString(36).slice(2,8).toUpperCase();
      if (MONGO_URI) {
        const inv = await Invite.create({ code, email: email || '', createdBy: req.user.email || 'admin' });
        invites.push(inv);
      } else {
        const inv = { code, email: email||'', used:false, id:memIdSeq++ };
        memInvites.push(inv);
        invites.push(inv);
      }
    }
    res.json({ invites });
  } catch (e) { res.status(500).json({ error: 'Invite creation failed' }); }
});

app.get('/api/admin/invites', authMw, adminMw, async (req, res) => {
  try {
    const invites = MONGO_URI
      ? await Invite.find().sort({ createdAt: -1 }).limit(100).lean()
      : memInvites.slice(-100).reverse();
    res.json({ invites });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/logs', authMw, adminMw, async (req, res) => {
  try {
    const logs = MONGO_URI
      ? await ChatLog.find().sort({ createdAt: -1 }).limit(100).lean()
      : memLogs.slice(-100).reverse();
    res.json({ logs });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ── Health ───────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({
  status: 'ok',
  model: 'claude-sonnet-4-20250514',
  db: MONGO_URI ? 'mongodb' : 'memory',
  uptime: Math.floor(process.uptime()),
}));

// ── Catch-all ────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 ByteChief AI v3.0 running on port ${PORT}`);
  console.log(`🤖  Model: claude-sonnet-4-20250514 (via Anthropic API)`);
  console.log(`🗄️  DB: ${MONGO_URI ? 'MongoDB Atlas' : 'In-memory'}`);
});
