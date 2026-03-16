/**
 * ByteChief AI — Backend Server
 * Node.js + Express + MongoDB Atlas + Groq AI
 * Author: Obasanjo Samuel — Tribal Chief Tech
 */

const express   = require('express');
const cors      = require('cors');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const mongoose  = require('mongoose');
const path      = require('path');
const Groq      = require('groq-sdk');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'bytechief-dev-secret-change-in-prod';
const GROQ_KEY    = process.env.GROQ_API_KEY;
const MONGO_URI   = process.env.MONGO_URI;
const ADMIN_USER  = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS  = process.env.ADMIN_PASSWORD || 'Obasanjo444@@';

// ── Groq ──────────────────────────────────────────────────────────────────────
const groq = GROQ_KEY ? new Groq({ apiKey: GROQ_KEY }) : null;

// ── MongoDB ───────────────────────────────────────────────────────────────────
if (MONGO_URI) {
  mongoose.connect(MONGO_URI)
    .then(async () => {
      console.log('✅ MongoDB connected');
      await seedAdmin();
    })
    .catch(err => console.error('❌ MongoDB:', err.message));
} else {
  console.warn('⚠️  No MONGO_URI — using in-memory storage');
}

// ── Schemas ───────────────────────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  email:      { type: String, required: true, unique: true, lowercase: true, trim: true },
  name:       { type: String, default: '' },
  password:   { type: String },
  provider:   { type: String, default: 'email' },
  role:       { type: String, default: 'user' },
  lastActive: { type: Date,   default: Date.now },
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
const ChatLog = mongoose.models.BCLog  || mongoose.model('BCLog',  LogSchema);

// ── In-memory fallback ────────────────────────────────────────────────────────
const memUsers = [];
const memLogs  = [];
let   memIdSeq = 1;

// ── Seed admin ────────────────────────────────────────────────────────────────
async function seedAdmin() {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || `${ADMIN_USER}@bytechief.ai`;
    const existing   = await User.findOne({ email: adminEmail });
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

// ── Core middleware ───────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..')));

const apiLimiter = rateLimit({ windowMs: 15*60*1000, max: 150, message: { error: 'Too many requests' } });
const chatLimit  = rateLimit({ windowMs:  1*60*1000, max: 25,  message: { error: 'Slow down — too many messages' } });
app.use('/api/', apiLimiter);

// ── Auth middleware ───────────────────────────────────────────────────────────
const authMw = (req, res, next) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token required' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
};
const adminMw = (req, res, next) =>
  req.user?.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' });

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 6)  return res.status(400).json({ error: 'Password must be at least 6 characters' });

    if (MONGO_URI) {
      if (await User.findOne({ email: email.toLowerCase() }))
        return res.status(409).json({ error: 'Email already registered' });
      const user = await User.create({
        email: email.toLowerCase(),
        name: name || email.split('@')[0],
        password: await bcrypt.hash(password, 10),
      });
      const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
      return res.status(201).json({ message: 'Account created!', token, user: { id: user._id, email: user.email, name: user.name, role: user.role } });
    }

    if (memUsers.find(u => u.email === email.toLowerCase()))
      return res.status(409).json({ error: 'Email already registered' });
    const user = { id: memIdSeq++, email: email.toLowerCase(), name: name || email.split('@')[0], password: await bcrypt.hash(password, 10), role: 'user', createdAt: new Date() };
    memUsers.push(user);
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ message: 'Account created!', token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) {
    console.error('Register:', e.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    if (MONGO_URI) {
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user || !user.password) return res.status(401).json({ error: 'Invalid credentials' });
      if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
      await User.findByIdAndUpdate(user._id, { lastActive: new Date() });
      const token = jwt.sign({ id: user._id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
      return res.json({ message: 'Welcome back!', token, user: { id: user._id, email: user.email, name: user.name, role: user.role } });
    }

    const user = memUsers.find(u => u.email === email.toLowerCase());
    if (!user || !await bcrypt.compare(password, user.password))
      return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Welcome back!', token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) {
    console.error('Login:', e.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Admin login
app.post('/api/auth/admin-login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const adminMatch = username === ADMIN_USER || username === (process.env.ADMIN_EMAIL || 'obasanjosamuel404@gmail.com');
    if (!adminMatch) return res.status(401).json({ error: 'Invalid credentials' });

    let valid = false;
    if (MONGO_URI) {
      try {
        const admin = await User.findOne({ email: `${ADMIN_USER}@bytechief.ai`, role: 'admin' });
        if (admin?.password) valid = await bcrypt.compare(password, admin.password);
      } catch {}
    }
    if (!valid) valid = (password === ADMIN_PASS);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: 'admin', username: ADMIN_USER, role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ message: 'Admin access granted', token, user: { username: ADMIN_USER, role: 'admin' } });
  } catch (e) {
    console.error('Admin login:', e.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/verify', authMw, (req, res) => res.json({ user: req.user }));

// ═══════════════════════════════════════════════════════════════════════════════
// AI CHAT — Groq llama-3.3-70b
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/chat', authMw, chatLimit, async (req, res) => {
  try {
    const { message, history = [] } = req.body;
    if (!message?.trim()) return res.status(400).json({ error: 'Message is required' });

    let rawResponse = '';

    if (groq) {
      const messages = [
        {
          role: 'system',
          content: `You are ByteChief AI — a smart, friendly, and powerful AI assistant created by Obasanjo Samuel at Tribal Chief Tech.
You help with: coding, learning, innovation, general questions, creative writing, math, and web commands.
For simulated phone commands, prefix your response with a structured action tag:
  - To call: start with ACTION:CALL:[target name or number]
  - To send SMS: start with ACTION:SMS:[target]:[message text]  
  - To open app: start with ACTION:OPEN:[app name]
For all other requests respond naturally, helpfully, and conversationally.
Be concise, warm, and use light formatting. You are running on Groq with llama-3.3-70b.`
        },
        ...history.slice(-8).map(h => ({ role: h.role, content: h.content })),
        { role: 'user', content: message },
      ];

      const completion = await groq.chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        messages,
        temperature: 0.72,
        max_tokens:  900,
      });
      rawResponse = completion.choices[0]?.message?.content || 'I could not process that. Please try again.';
    } else {
      rawResponse = mockAI(message);
    }

    // Parse action commands
    let action = null;
    const callM = rawResponse.match(/ACTION:CALL:(.+)/i);
    const smsM  = rawResponse.match(/ACTION:SMS:([^:]+):(.+)/i);
    const openM = rawResponse.match(/ACTION:OPEN:(.+)/i);
    if (callM) action = { type: 'call', target: callM[1].trim() };
    if (smsM)  action = { type: 'sms',  target: smsM[1].trim(), smsMessage: smsM[2].trim() };
    if (openM) action = { type: 'open', target: openM[1].trim() };

    // Strip action tags from display response
    const displayResponse = rawResponse.replace(/ACTION:[A-Z]+:[^\n]*/gi, '').trim() || rawResponse;

    // Log it
    try {
      if (MONGO_URI) {
        const userName = req.user.name || req.user.email?.split('@')[0] || 'User';
        await ChatLog.create({
          userId:    req.user.id,
          userEmail: req.user.email,
          userName,
          command:   message,
          response:  displayResponse,
          model:     groq ? 'groq-llama-3.3-70b' : 'mock',
        });
      } else {
        memLogs.push({ id: memLogs.length + 1, userId: req.user.id, userEmail: req.user.email, command: message, response: displayResponse, createdAt: new Date() });
      }
    } catch (logErr) { console.warn('Log error:', logErr.message); }

    res.json({ response: displayResponse, action, timestamp: new Date().toISOString() });
  } catch (e) {
    console.error('Chat error:', e.message);
    res.status(500).json({ error: 'AI service error. Please try again.' });
  }
});

function mockAI(msg) {
  const m = msg.toLowerCase().trim();
  if (m.match(/^(hi|hello|hey)/)) return `Hello! 👋 I'm ByteChief AI — your intelligent assistant. How can I help you today?`;
  if (m.includes('who are you'))  return `I'm ByteChief AI, built by Obasanjo Samuel at Tribal Chief Tech 🚀 I'm here to help you with coding, learning, and more!`;
  if (m.includes('call'))         return `ACTION:CALL:${m.split('call').pop().trim()}\n📞 Initiating call...`;
  if (m.includes('sms') || m.includes('message')) return `ACTION:SMS:contact:${msg}\n📨 Message sent!`;
  if (m.includes('open'))         return `ACTION:OPEN:${m.split('open').pop().trim()}\n📱 Opening app...`;
  if (m.includes('help'))         return `I can help with:\n• 💻 Coding & debugging\n• 📚 Learning & research\n• 📞 Simulated calls & SMS\n• 💡 Ideas & innovation\n• And much more! Just ask.`;
  return `You said: "${msg}"\n\nI'm ByteChief AI and I'm ready to assist! (Note: Connect a Groq API key for full AI responses) 🤖`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// USER ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/user/profile', authMw, async (req, res) => {
  try {
    if (MONGO_URI) {
      const u = await User.findById(req.user.id).select('-password');
      return u ? res.json(u) : res.status(404).json({ error: 'User not found' });
    }
    const u = memUsers.find(u => u.id == req.user.id);
    if (!u) return res.status(404).json({ error: 'User not found' });
    const { password, ...safe } = u;
    res.json(safe);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch profile' }); }
});

app.get('/api/commands/history', authMw, async (req, res) => {
  try {
    if (MONGO_URI) {
      const logs = await ChatLog.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(50);
      return res.json({ logs });
    }
    res.json({ logs: memLogs.filter(l => l.userId == req.user.id).reverse().slice(0, 50) });
  } catch (e) { res.status(500).json({ error: 'Failed to fetch history' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/stats', authMw, adminMw, async (req, res) => {
  try {
    if (MONGO_URI) {
      const dayAgo = new Date(Date.now() - 86400000);
      const [totalUsers, totalCommands, activeUsers, recentCommands] = await Promise.all([
        User.countDocuments({ role: 'user' }),
        ChatLog.countDocuments(),
        User.countDocuments({ lastActive: { $gte: dayAgo } }),
        ChatLog.countDocuments({ createdAt:  { $gte: dayAgo } }),
      ]);
      return res.json({ stats: { totalUsers, totalCommands, activeUsers, recentCommands } });
    }
    res.json({ stats: { totalUsers: memUsers.length, totalCommands: memLogs.length, activeUsers: 0, recentCommands: 0 } });
  } catch (e) { res.status(500).json({ error: 'Stats unavailable' }); }
});

app.get('/api/admin/users', authMw, adminMw, async (req, res) => {
  try {
    if (MONGO_URI) {
      const users = await User.find({ role: 'user' }).select('-password').sort({ createdAt: -1 });
      return res.json({ users });
    }
    res.json({ users: memUsers.map(({ password, ...u }) => u) });
  } catch (e) { res.status(500).json({ error: 'Failed to fetch users' }); }
});

app.get('/api/admin/logs', authMw, adminMw, async (req, res) => {
  try {
    if (MONGO_URI) {
      const logs = await ChatLog.find().sort({ createdAt: -1 }).limit(200);
      return res.json({ logs });
    }
    res.json({ logs: memLogs.slice().reverse().slice(0, 200) });
  } catch (e) { res.status(500).json({ error: 'Failed to fetch logs' }); }
});

app.delete('/api/admin/users/:id', authMw, adminMw, async (req, res) => {
  try {
    if (MONGO_URI) {
      await User.findByIdAndDelete(req.params.id);
      await ChatLog.deleteMany({ userId: req.params.id });
      return res.json({ message: 'User deleted' });
    }
    const i = memUsers.findIndex(u => String(u.id) === req.params.id);
    if (i > -1) memUsers.splice(i, 1);
    res.json({ message: 'User deleted' });
  } catch (e) { res.status(500).json({ error: 'Failed to delete user' }); }
});

// Health
app.get('/api/health', (req, res) => res.json({
  status: 'healthy', app: 'ByteChief AI', version: '1.0.0',
  ai: groq ? 'Groq llama-3.3-70b' : 'mock',
  db: MONGO_URI ? 'MongoDB Atlas' : 'in-memory',
  timestamp: new Date(),
}));

// Serve HTML pages
const pages = ['dashboard', 'about', 'terms', 'login', 'signup', 'admin-login', 'admin-dashboard'];
pages.forEach(p => {
  app.get(`/${p}`, (req, res) => res.sendFile(path.join(__dirname, '..', `${p}.html`)));
  app.get(`/${p}.html`, (req, res) => res.sendFile(path.join(__dirname, '..', `${p}.html`)));
});
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '..', 'index.html')));
app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🤖 ByteChief AI on port ${PORT}`);
  console.log(`   AI  : ${groq ? 'Groq llama-3.3-70b ✅' : 'Mock mode'}`);
  console.log(`   DB  : ${MONGO_URI ? 'MongoDB Atlas ✅' : 'In-memory'}\n`);
});

module.exports = app;
