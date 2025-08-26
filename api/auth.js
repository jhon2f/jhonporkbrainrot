const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const router = express.Router();

const sessions = new Map();

// Limit how often someone can request a new session
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many auth attempts' }
});

router.use(authLimiter);

// Helper to get IP
function getIP(req) {
  return req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || req.ip || 'unknown';
}

// Generate a random session token
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Create a new session
router.post('/', (req, res) => {
  try {
    const sessionId = generateToken();
    const sessionData = {
      ip: getIP(req),
      timestamp: Date.now(),
      expiresAt: Date.now() + (30 * 60 * 1000), // 30 minutes
      requestCount: 0,
      maxRequests: 200
    };

    sessions.set(sessionId, sessionData);

    res.json({
      token: sessionId,
      expiresIn: 1800,
      requestLimit: 200
    });
  } catch (error) {
    res.status(500).json({ error: 'Auth failed' });
  }
});

// Validate session automatically
function validateSession(req) {
  const token = req.headers['x-session-token'];

  // If no token, throw error automatically
  if (!token) throw new Error('No token provided');

  const session = sessions.get(token);
  if (!session) throw new Error('Invalid session');

  // Check expiry
  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    throw new Error('Session expired');
  }

  // Check request count
  if (session.requestCount >= session.maxRequests) {
    throw new Error('Rate limit exceeded');
  }

  // Increment request count automatically
  session.requestCount++;
  sessions.set(token, session);

  return session;
}

// Automatic cleanup of expired sessions every minute
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (session.expiresAt < now) sessions.delete(id);
  }
}, 60000);

// Expose validateSession for your routes
router.validateSession = validateSession;

module.exports = router;
