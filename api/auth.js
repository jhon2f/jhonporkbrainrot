import crypto from 'crypto';

// Use global to persist across function invocations in serverless environment
global.sessions = global.sessions || new Map();
global.authRateLimits = global.authRateLimits || new Map();

const sessions = global.sessions;
const authRateLimits = global.authRateLimits;

// Helper to get client IP
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.headers['cf-connecting-ip'] ||
         req.socket.remoteAddress || 
         req.connection.remoteAddress ||
         'unknown';
}

// Generate a session token using IP and timestamp for consistency
function generateToken(ip) {
  const timestamp = Date.now();
  const randomBytes = crypto.randomBytes(16).toString('hex');
  const hash = crypto.createHash('sha256').update(`${ip}-${timestamp}-${randomBytes}`).digest('hex');
  return hash;
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
    const sessionId = generateToken(ip);
    const sessionData = {
      ip,
      timestamp: Date.now(),
      expiresAt: Date.now() + 30 * 60 * 1000, // 30 minutes
      requestCount: 0,
      maxRequests: 200
    };

    sessions.set(sessionId, sessionData);
    console.log(`Created session ${sessionId} for IP ${ip}`);

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

  console.log(`Validating token ${token}, sessions size: ${sessions.size}`);

  const session = sessions.get(token);
  if (!session) {
    console.log('Session not found, available sessions:', Array.from(sessions.keys()));
    throw new Error('Invalid session');
  }

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
  console.log(`Session validated, request count: ${session.requestCount}`);
  return session;
}

// Clean up expired sessions (run on each request since setInterval won't work reliably)
function cleanupExpiredSessions() {
  const now = Date.now();
  let cleaned = 0;
  for (const [id, session] of sessions.entries()) {
    if (session.expiresAt < now) {
      sessions.delete(id);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    console.log(`Cleaned up ${cleaned} expired sessions`);
  }
}

// Main handler
export default async function handler(req, res) {
  // Clean up expired sessions on each request
  cleanupExpiredSessions();

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
