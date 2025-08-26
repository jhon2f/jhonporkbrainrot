import crypto from 'crypto';

const authRateLimits = new Map();

// Helper to get client IP
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.headers['cf-connecting-ip'] ||
         req.socket.remoteAddress || 
         req.connection.remoteAddress ||
         'unknown';
}

// JWT-like token generation (simplified)
function generateJWT(payload) {
  const secret = process.env.JWT_SECRET || 'default-secret-change-in-production';
  const header = { alg: 'HS256', typ: 'JWT' };
  
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');
  
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

// JWT validation
function validateJWT(token) {
  const secret = process.env.JWT_SECRET || 'default-secret-change-in-production';
  const parts = token.split('.');
  
  if (parts.length !== 3) {
    throw new Error('Invalid token format');
  }
  
  const [encodedHeader, encodedPayload, signature] = parts;
  
  // Verify signature
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');
  
  if (signature !== expectedSignature) {
    throw new Error('Invalid token signature');
  }
  
  // Decode payload
  const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
  
  // Check expiration
  if (Date.now() > payload.exp) {
    throw new Error('Token expired');
  }
  
  return payload;
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
    const now = Date.now();
    const payload = {
      ip,
      iat: now,
      exp: now + 30 * 60 * 1000, // 30 minutes
      requestCount: 0,
      maxRequests: 200
    };

    const token = generateJWT(payload);
    console.log(`Created JWT token for IP ${ip}`);

    res.status(200).json({
      token,
      expiresIn: 1800,
      requestLimit: 200
    });
  } catch (err) {
    console.error('Auth error:', err);
    res.status(500).json({ error: 'Auth failed' });
  }
}

// Validate session (exported for use in other functions)
function validateSession(req) {
  const token = req.headers['x-session-token'];
  if (!token) throw new Error('No token provided');

  console.log(`Validating JWT token`);
  
  try {
    const payload = validateJWT(token);
    console.log(`JWT validated for IP ${payload.ip}, issued at ${new Date(payload.iat).toISOString()}`);
    return payload;
  } catch (err) {
    console.log(`JWT validation failed: ${err.message}`);
    throw new Error(`Invalid session: ${err.message}`);
  }
}

// Clean up expired rate limit entries
function cleanupRateLimits() {
  const now = Date.now();
  let cleaned = 0;
  for (const [ip, requests] of authRateLimits.entries()) {
    const validRequests = requests.filter(time => now - time < 15 * 60 * 1000);
    if (validRequests.length === 0) {
      authRateLimits.delete(ip);
      cleaned++;
    } else {
      authRateLimits.set(ip, validRequests);
    }
  }
  if (cleaned > 0) {
    console.log(`Cleaned up ${cleaned} expired rate limit entries`);
  }
}

// Main handler
export default async function handler(req, res) {
  // Clean up expired rate limits
  cleanupRateLimits();

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

  if (req.method === 'GET') {
    // Health check or token validation endpoint
    return res.status(200).json({ 
      status: 'operational',
      message: 'Auth service ready' 
    });
  }

  res.status(405).json({ error: 'Method not allowed' });
}

// Export validateSession for other modules
export { validateSession };
