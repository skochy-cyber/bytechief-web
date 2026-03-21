/**
 * ByteChief AI — Backend Server v2.1 (Render-ready)
 * Node.js + Express + MongoDB Atlas + Groq AI + Pollinations Image Gen
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

const app        = express();
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'bytechief-dev-secret-change-in-prod';
const GROQ_KEY   = process.env.GROQ_API_KEY;
const MONGO_URI  = process.env.MONGO_URI;
const ADMIN_USER = process.env.ADMIN_USERNAME || 'obasanjosamuel404';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'Obasanjo444@@';
const ADMIN_EMAIL_ENV = process.env.ADMIN_EMAIL || 'obasanjosamuel404@gmail.com';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

app.set('trust proxy', 1);

// ── Groq ────────────────────────────────────────────────────────────────────
const groq = GROQ_KEY ? new Groq({ apiKey: GROQ_KEY }) : null;

// ── MongoDB ──────────────────────────────────────────────────────────────────
if (MONGO_URI) {
  mongoose.connect(MONGO_URI)
    .then(async () => { console.log('✅ MongoDB connected'); await seedAdmin(); })
    .catch(err => console.error('❌ MongoDB:', err.message));
} else {
  console.warn('⚠️  No MONGO_URI — using in-memory storage');
}

// ── Schemas ──────────────────────────────────────────────────────────────────
// FIX #1: Use Object instead of Map — Map breaks Object.keys() and JSON serialization
const UserSchema = new mongoose.Schema({
  email:      { type: String, required: true, unique: true, lowercase: true, trim: true },
  name:       { type: String, default: '' },
  password:   { type: String },
  role:       { type: String, default: 'user' },
  isInvited:  { type: Boolean, default: false },
  inviteCode: { type: String, default: '' },
  lastActive: { type: Date, default: Date.now },
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
  model:     { type: String, default: 'groq' },
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
// FIX #5: Restrict CORS to allowed origin
app.use(cors({
  origin: ALLOWED_ORIGIN === '*' ? '*' : ALLOWED_ORIGIN,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..')));

const apiLimiter = rateLimit({ windowMs: 15*60*1000, max: 200, message: { error: 'Too many requests' } });
const chatLimit  = rateLimit({ windowMs:  1*60*1000, max:  20, message: { error: 'Slow down — too many messages' } });
app.use('/api/', apiLimiter);

const authMw = (req, res, next) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token required' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
};
const adminMw = (req, res, next) =>
  req.user?.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' });

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
        isInvited: true, inviteCode,
      });
      invite.used = true; invite.usedBy = email; await invite.save();
      return res.json({ token: makeToken(user), user: { id: user._id, email: user.email, name: user.name, role: user.role } });
    } else {
      const invite = memInvites.find(i => i.code === inviteCode.trim().toUpperCase() && !i.used);
      if (!invite) return res.status(403).json({ error: 'Invalid or already used invite code' });
      if (memUsers.find(u => u.email === email.toLowerCase())) return res.status(409).json({ error: 'Email already registered' });
      const user = { id: memIdSeq++, email: email.toLowerCase(), name: name || '', password: await bcrypt.hash(password, 10), role: 'user', isInvited: true, memory: { contacts: {}, preferences: {}, facts: [] }, createdAt: new Date() };
      memUsers.push(user); invite.used = true; invite.usedBy = email;
      return res.json({ token: makeToken(user), user: { id: user.id, email: user.email, name: user.name, role: user.role } });
    }
  } catch (e) { console.error(e); res.status(500).json({ error: 'Registration failed' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const user = MONGO_URI
      ? await User.findOne({ email: email.toLowerCase() })
      : memUsers.find(u => u.email === email.toLowerCase());
    if (!user || !user.password) return res.status(401).json({ error: 'Invalid credentials' });
    if (!(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
    if (MONGO_URI) await User.findByIdAndUpdate(user._id, { lastActive: new Date() });
    res.json({ token: makeToken(user), user: { id: user._id || user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Login failed' }); }
});

// Admin login — accepts username OR email
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    let user;
    if (MONGO_URI) {
      // Accept login with email OR admin username
      user = await User.findOne({
        $or: [
          { email: ADMIN_EMAIL_ENV, role: 'admin' },
          { email: username.toLowerCase(), role: 'admin' },
        ]
      });
    } else {
      user = memUsers.find(u => u.role === 'admin');
    }
    if (!user) return res.status(401).json({ error: 'Admin not found' });
    // Accept username match OR email match
    const usernameMatch = username === ADMIN_USER || username === ADMIN_EMAIL_ENV || username === user.email;
    if (!usernameMatch) return res.status(401).json({ error: 'Invalid credentials' });
    if (!(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ token: makeToken(user), user: { id: user._id || user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) { res.status(500).json({ error: 'Admin login failed' }); }
});

app.get('/api/me', authMw, async (req, res) => {
  try {
    const user = MONGO_URI
      ? await User.findById(req.user.id).select('-password')
      : (() => { const u = memUsers.find(u => u.id === req.user.id); if (u) { const { password, ...r } = u; return r; } })();
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// FIX #8: Forgot password route
app.post('/api/forgot-password', async (req, res) => {
  // For now just return success — full email reset requires email service config
  // The admin can reset manually via admin dashboard
  res.json({ message: 'If that email exists, contact your admin to reset your password.' });
});

// ══════════════════════════════════════════════════════════════════════════════
// MEMORY ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/memory', authMw, async (req, res) => {
  try {
    if (MONGO_URI) {
      const user = await User.findById(req.user.id).select('memory name');
      // FIX #1: Ensure plain objects returned (not Mongoose Map objects)
      const memory = user?.memory?.toObject ? user.memory.toObject() : (user?.memory || {});
      return res.json({
        name:   user?.name || '',
        memory: {
          contacts:    memory.contacts    || {},
          preferences: memory.preferences || {},
          facts:       memory.facts       || [],
        }
      });
    }
    const u = memUsers.find(u => u.id === req.user.id);
    res.json({ memory: u?.memory || {}, name: u?.name || '' });
  } catch (e) { res.status(500).json({ error: 'Failed to fetch memory' }); }
});

app.put('/api/memory', authMw, async (req, res) => {
  try {
    const { contacts, preferences, facts } = req.body;

    // FIX #4: Validate memory input size
    if (contacts && Object.keys(contacts).length > 100)
      return res.status(400).json({ error: 'Too many contacts (max 100)' });
    if (facts && facts.length > 30)
      return res.status(400).json({ error: 'Too many facts (max 30)' });
    // Validate string lengths
    if (contacts) {
      for (const [k, v] of Object.entries(contacts)) {
        if (String(k).length > 100 || String(v).length > 200)
          return res.status(400).json({ error: 'Contact name/number too long' });
      }
    }
    if (facts) {
      for (const f of facts) {
        if (String(f).length > 300) return res.status(400).json({ error: 'Fact too long (max 300 chars)' });
      }
    }

    if (MONGO_URI) {
      const update = {};
      if (contacts)    update['memory.contacts']    = contacts;
      if (preferences) update['memory.preferences'] = preferences;
      if (facts)       update['memory.facts']       = facts;
      await User.findByIdAndUpdate(req.user.id, { $set: update });
    } else {
      const u = memUsers.find(u => u.id === req.user.id);
      if (u) {
        if (!u.memory) u.memory = {};
        if (contacts)    u.memory.contacts    = contacts;
        if (preferences) u.memory.preferences = preferences;
        if (facts)       u.memory.facts       = facts;
      }
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Failed to update memory' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// AI CHAT
// ══════════════════════════════════════════════════════════════════════════════

const SYSTEM_PROMPT = `You are ByteChief AI — a powerful, all-in-one AI assistant created by Obasanjo Samuel (also known as "Tribal Chief"), a Nigerian developer and tech entrepreneur from Tribal Chief Tech.

YOUR IDENTITY:
- Name: ByteChief AI
- Creator: Obasanjo Samuel — Tribal Chief Tech
- You are NOT Claude, GPT, Gemini, or any other AI. You are ONLY ByteChief AI.

YOUR PERSONALITY — switch based on context:
- Casual chat / jokes: Warm, funny, witty with Nigerian flavor. You understand Pidgin English, Yoruba slang, everyday banter
- Coding / technical: Precise, professional. Always give working code with explanations in markdown code blocks
- Business / finance: Sharp and practical with Nigerian market knowledge (Naira ₦, Nigerian banks, local context)
- School / research: Clear, patient, educational
- Motivation: Energetic and inspiring
- You understand and respond in ALL languages — always reply in the same language the user speaks

YOUR CAPABILITIES:
1. General conversation — any topic
2. Coding — write, debug, and explain code in any language
3. School / research — essays, assignments, summaries, explanations
4. Nigerian context — culture, slang, Naira currency, local brands, Nigerian news
5. Crypto & finance — concepts, analysis, trends (always add ⚠️ DYOR disclaimer)
6. Humor — Nigerian jokes, worldwide comedy, witty banter
7. Motivation — powerful quotes and pep talks
8. Current events — share knowledge (remind user to verify latest news)
9. Image & logo generation — when user asks to generate/create/draw/design an image or logo, respond with exactly: [IMAGE: detailed visual description]

MEMORY — you have the user's saved information:
- Use their name naturally in conversation when known
- Reference saved contacts, preferences, and facts when relevant
- When user says "remember that...", "my [x] is...", "save this...", acknowledge you'll store it

COMMAND SHORTCUTS — when user says these, confirm naturally:
- "call [name]" → say "Calling [name] now!"
- "open [app]" → say "Opening [app]!"
- "text [name]" → say "Sending message to [name]!"

RULES:
- Be helpful, real, and direct
- Never be preachy or add unnecessary warnings
- Keep responses concise unless detail is needed
- For finance/crypto always end with ⚠️ DYOR (Do Your Own Research)
- You are the Chief — act like it`;

app.post('/api/chat', authMw, chatLimit, async (req, res) => {
  const { message, history = [], memory = {} } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });
  if (String(message).length > 4000) return res.status(400).json({ error: 'Message too long' });

  try {
    let reply;
    if (groq) {
      let memCtx = '';
      if (memory.name) memCtx += `\nUser's name: ${memory.name}`;
      if (memory.contacts && Object.keys(memory.contacts).length)
        memCtx += `\nSaved contacts: ${JSON.stringify(memory.contacts)}`;
      if (memory.preferences && Object.keys(memory.preferences).length)
        memCtx += `\nUser preferences: ${JSON.stringify(memory.preferences)}`;
      if (memory.facts?.length)
        memCtx += `\nThings to remember about user: ${memory.facts.join('; ')}`;

      const now = new Date();
      const timeStr = now.toLocaleString('en-NG', { timeZone: 'Africa/Lagos', weekday:'long', year:'numeric', month:'long', day:'numeric', hour:'2-digit', minute:'2-digit', hour12:true });
      const timeCtx = `\nCurrent date and time in Nigeria (WAT, UTC+1): ${timeStr}`;

      const completion = await groq.chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: SYSTEM_PROMPT + timeCtx + (memCtx ? `\n\nUSER MEMORY:${memCtx}` : '') },
          ...history.slice(-12).map(h => ({ role: h.role, content: String(h.content).slice(0, 2000) })),
          { role: 'user', content: message },
        ],
        max_tokens: 1024,
        temperature: 0.75,
      });
      reply = completion.choices[0]?.message?.content || 'No response generated.';
    } else {
      reply = `[Mock mode — no GROQ_API_KEY set] You said: "${message}"`;
    }

    // Image generation trigger
    let imageUrl = null;
    const imgMatch = reply.match(/\[IMAGE:\s*(.+?)\]/i);
    if (imgMatch) {
      const prompt = encodeURIComponent(imgMatch[1].trim());
      imageUrl = `https://image.pollinations.ai/prompt/${prompt}?width=512&height=512&nologo=true`;
      reply = reply.replace(/\[IMAGE:\s*.+?\]/i, '').trim();
      if (!reply) reply = "Here's your generated image!";
    }

    // Save log
    const logData = {
      userId: req.user.id, userEmail: req.user.email, userName: req.user.name,
      command: message, response: reply,
      type: imageUrl ? 'image' : 'chat',
      model: groq ? 'groq-llama-3.3-70b' : 'mock',
    };
    if (MONGO_URI) {
      await ChatLog.create(logData);
      await User.findByIdAndUpdate(req.user.id, { lastActive: new Date() });
    } else {
      memLogs.push({ ...logData, id: memIdSeq++, createdAt: new Date() });
    }

    res.json({ reply, imageUrl });
  } catch (e) {
    console.error('Chat error:', e);
    res.status(500).json({ error: 'AI request failed. Please try again.' });
  }
});

// Direct image endpoint
app.post('/api/image', authMw, async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt required' });
  const imageUrl = `https://image.pollinations.ai/prompt/${encodeURIComponent(prompt.trim())}?width=512&height=512&nologo=true`;
  res.json({ imageUrl, prompt });
});

// Chat history
app.get('/api/history', authMw, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const logs = MONGO_URI
      ? await ChatLog.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(limit).lean()
      : memLogs.filter(l => l.userId === req.user.id).slice(-limit).reverse();
    res.json({ logs });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// INVITE SYSTEM
// ══════════════════════════════════════════════════════════════════════════════

function generateInviteCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = 'BC-';
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

app.get('/api/invite/validate/:code', async (req, res) => {
  try {
    const code = req.params.code.trim().toUpperCase();
    if (MONGO_URI) {
      const inv = await Invite.findOne({ code, used: false });
      return res.json({ valid: !!inv, email: inv?.email || '' });
    }
    const inv = memInvites.find(i => i.code === code && !i.used);
    res.json({ valid: !!inv, email: inv?.email || '' });
  } catch (e) { res.status(500).json({ error: 'Validation failed' }); }
});

app.post('/api/admin/invites', authMw, adminMw, async (req, res) => {
  try {
    const { count = 1, email = '' } = req.body;
    const created = [];
    for (let i = 0; i < Math.min(count, 50); i++) {
      const code = generateInviteCode();
      if (MONGO_URI) {
        created.push(await Invite.create({ code, email: email.toLowerCase() }));
      } else {
        const inv = { id: memIdSeq++, code, email: email.toLowerCase(), used: false, usedBy: '', createdAt: new Date() };
        memInvites.push(inv); created.push(inv);
      }
    }
    res.json({ ok: true, invites: created });
  } catch (e) { res.status(500).json({ error: 'Failed to create invites' }); }
});

app.get('/api/admin/invites', authMw, adminMw, async (req, res) => {
  try {
    const invites = MONGO_URI
      ? await Invite.find().sort({ createdAt: -1 }).lean()
      : memInvites;
    res.json({ invites });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/invites/:id', authMw, adminMw, async (req, res) => {
  try {
    if (MONGO_URI) { await Invite.findByIdAndDelete(req.params.id); }
    else { const idx = memInvites.findIndex(i => String(i.id) === req.params.id); if (idx !== -1) memInvites.splice(idx, 1); }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/stats', authMw, adminMw, async (req, res) => {
  try {
    let totalUsers, totalLogs, totalInvites, recentUsers;
    if (MONGO_URI) {
      [totalUsers, totalLogs, totalInvites, recentUsers] = await Promise.all([
        User.countDocuments(), ChatLog.countDocuments(),
        Invite.countDocuments({ used: false }),
        User.find().sort({ createdAt: -1 }).limit(5).select('-password').lean(),
      ]);
    } else {
      totalUsers = memUsers.length; totalLogs = memLogs.length;
      totalInvites = memInvites.filter(i => !i.used).length;
      recentUsers  = memUsers.slice(-5).map(({ password, ...u }) => u);
    }
    res.json({ totalUsers, totalLogs, totalInvites, recentUsers });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/users', authMw, adminMw, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
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
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

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
      if (idx === -1) return res.status(404).json({ error: 'Not found' });
      if (memUsers[idx].role === 'admin') return res.status(403).json({ error: 'Cannot delete admin' });
      memUsers.splice(idx, 1);
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/logs', authMw, adminMw, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
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
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// Admin reset password for a user
app.post('/api/admin/users/:id/reset-password', authMw, adminMw, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 chars' });
    if (MONGO_URI) {
      await User.findByIdAndUpdate(req.params.id, { password: await bcrypt.hash(newPassword, 10) });
    } else {
      const u = memUsers.find(u => String(u.id) === req.params.id);
      if (u) u.password = await bcrypt.hash(newPassword, 10);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ── Health ───────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({
  status: 'ok', version: '2.1.0',
  ai: groq ? 'groq-connected' : 'mock-mode',
  database: MONGO_URI ? 'mongodb-atlas' : 'in-memory',
  uptime: Math.floor(process.uptime()),
}));

app.use('/api/', (req, res) => res.status(404).json({ error: 'API endpoint not found' }));

app.listen(PORT, () => {
  console.log(`\n⚡ ByteChief AI Server v2.1`);
  console.log(`🌐  http://localhost:${PORT}`);
  console.log(`🤖  AI: ${groq ? 'Groq connected' : 'Mock mode'}`);
  console.log(`🗄️   DB: ${MONGO_URI ? 'MongoDB Atlas' : 'In-memory'}`);
  console.log(`🔐  Admin: ${ADMIN_EMAIL_ENV}`);
  console.log(`🎟️   Invite-only registration: ENABLED\n`);
});
