import crypto from 'crypto';

const sessions = new Map();
const authRateLimits = new Map();

// Helper to get client IP
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.headers['cf-connecting-ip'] ||
         req.socket.remoteAddress || 
         req.connection.remoteAddress ||
         'unknown';
}

// Generate a random session token
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

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
    console.error('Auth error:', err);
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

// Automatic cleanup of expired sessions
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (session.expiresAt < now) sessions.delete(id);
  }
}, 60000);

// Main handler
export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method === 'POST') {
    return createSession(req, res);
  }

  res.status(405).json({ error: 'Method not allowed' });
}

// Export validateSession for other modules
export { validateSession };
