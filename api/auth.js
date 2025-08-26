// api/auth.js
import crypto from 'crypto';

const sessions = new Map();

// Helper to get client IP
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
}

// Generate a random session token
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Rate limiter map for auth requests
const authRateLimits = new Map();

// Check rate limit for auth
function checkAuthRateLimit(ip) {
  const now = Date.now();
  if (!authRateLimits.has(ip)) authRateLimits.set(ip, []);
  const requests = authRateLimits.get(ip).filter(time => now - time < 15 * 60 * 1000); // 15 min
  if (requests.length >= 10) return false;
  requests.push(now);
  authRateLimits.set(ip, requests);
  return true;
}

// Create a new session
async function createSession(req, res) {
  const ip = getIP(req);

  if (!checkAuthRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many auth attempts' });
  }

  try {
    const sessionId = generateToken();
    const sessionData = {
      ip,
      timestamp: Date.now(),
      expiresAt: Date.now() + 30 * 60 * 1000, // 30 minutes
      requestCount: 0,
      maxRequests: 200
    };

    sessions.set(sessionId, sessionData);

    res.status(200).json({
      token: sessionId,
      expiresIn: 1800,
      requestLimit: 200
    });
  } catch (err) {
    res.status(500).json({ error: 'Auth failed' });
  }
}

// Validate session
function validateSession(req) {
  const token = req.headers['x-session-token'];
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

  // Increment request count
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

// Serverless handler
export default async function handler(req, res) {
  if (req.method === 'POST') {
    return createSession(req, res);
  }

  res.status(405).json({ error: 'Method not allowed' });
}

// Expose validateSession for other modules
export { validateSession };
