/**
 * ByteChief AI — Backend Server (Render-ready)
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

// ── TRUST PROXY (Fix X-Forwarded-For errors on Render) ─────────────────────────
app.set('trust proxy', 1); // important for express-rate-limit behind Render/Vercel/Heroku

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

// ── Rate limiters ─────────────────────────────────────────────────────────────
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

// ── Your existing routes remain unchanged ──────────────────────────────────────
// [AUTH ROUTES, AI CHAT ROUTES, USER ROUTES, ADMIN ROUTES, Health check, HTML pages]

app.listen(PORT, () => {
  console.log(`\n🤖 ByteChief AI on port ${PORT}`);
  console.log(`   AI  : ${groq ? 'Groq llama-3.3-70b ✅' : 'Mock mode'}`);
  console.log(`   DB  : ${MONGO_URI ? 'MongoDB Atlas ✅' : 'In-memory'}\n`);
});

module.exports = app;