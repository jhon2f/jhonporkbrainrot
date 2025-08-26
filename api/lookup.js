import crypto from 'crypto';

const rateLimits = new Map();

// JWT validation (duplicated to avoid import issues in serverless)
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

// Validate session
function validateSession(req) {
  const token = req.headers['x-session-token'];
  if (!token) throw new Error('No token provided');

  console.log(`Validating JWT token in lookup`);
  
  try {
    const payload = validateJWT(token);
    console.log(`JWT validated in lookup for IP ${payload.ip}`);
    return payload;
  } catch (err) {
    console.log(`JWT validation failed in lookup: ${err.message}`);
    throw new Error(`Invalid session: ${err.message}`);
  }
}

// Rate limiter
function checkRateLimit(ip) {
  const now = Date.now();
  if (!rateLimits.has(ip)) rateLimits.set(ip, []);
  const requests = rateLimits.get(ip).filter(time => now - time < 2 * 60 * 1000); // 2 min
  if (requests.length >= 15) return false;
  requests.push(now);
  rateLimits.set(ip, requests);
  return true;
}

// Get client IP
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.headers['cf-connecting-ip'] ||
         req.socket.remoteAddress || 
         req.connection.remoteAddress ||
         'unknown';
}

// Detect type function
function detectType(term) {
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(term)) return 'email';
  if (/^[\+]?[1-9][\d\s\-\(\)]{7,15}$/.test(term)) return 'phone';
  if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(term)) return 'ip';
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(term) && !term.startsWith('http')) return 'domain';
  return 'username';
}

// OSINT query
async function queryOSINT(query, type) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    const response = await fetch('https://osintdog.com/api/search', {
      method: 'POST',
      headers: {
        'X-API-Key': process.env.API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ field: [{ [type]: query }] }),
      signal: controller.signal
    });

    clearTimeout(timeout);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    return await response.json();
  } catch (err) {
    clearTimeout(timeout);
    console.error('OSINT query error:', err.message);
    throw err;
  }
}

// IdLeak query
async function queryIdLeak(params) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    const response = await fetch('https://idleakcheck.com/api/v1/search', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.IDLEAK_API_KEY}`
      },
      body: JSON.stringify(params),
      signal: controller.signal
    });

    clearTimeout(timeout);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    return await response.json();
  } catch (err) {
    clearTimeout(timeout);
    console.error('IdLeak query error:', err.message);
    throw err;
  }
}

// Main handler
export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const clientIP = getIP(req);

  // Health check endpoint
  if (req.method === 'GET' && req.url?.endsWith('/health')) {
    return res.status(200).json({
      status: 'operational',
      supported_types: ['email', 'username', 'phone', 'ip', 'domain', 'idleak']
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Validate session
  try {
    const session = validateSession(req);
    console.log(`Session validated for IP: ${session.ip}`);
  } catch (err) {
    console.error(`Session validation failed: ${err.message}`);
    return res.status(401).json({ error: err.message });
  }

  // Check rate limit
  if (!checkRateLimit(clientIP)) {
    return res.status(429).json({ error: 'Rate limit exceeded' });
  }

  try {
    const { query, type } = req.body;

    if (!query || typeof query !== 'string' || query.length < 2 || query.length > 1000) {
      return res.status(400).json({ error: 'Invalid query parameter' });
    }

    let results;
    let searchType = type;

    if (type === 'idleak') {
      let params;
      try {
        params = JSON.parse(query);
      } catch (e) {
        return res.status(400).json({ error: 'Invalid JSON in query for idleak' });
      }

      if (!process.env.IDLEAK_API_KEY) {
        return res.status(503).json({ error: 'IdLeak service not configured' });
      }

      results = await queryIdLeak(params);
      searchType = 'idleak';
    } else {
      if (!process.env.API_KEY) {
        return res.status(503).json({ error: 'OSINT service not configured' });
      }

      const sanitized = query.replace(/[<>"'\x00-\x1f\x7f-\x9f]/g, '').trim();
      searchType = type === 'keyword' ? 'username' : (type || detectType(sanitized));
      results = await queryOSINT(sanitized, searchType);
    }

    res.status(200).json({
      success: true,
      search_term: type === 'idleak' ? 'idleak_search' : query,
      search_type: searchType,
      investigation_results: results,
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    console.error('Lookup error:', err.message);

    if (err.name === 'AbortError') {
      return res.status(408).json({ error: 'Request timeout' });
    }
    
    if (err.message.includes('HTTP') || err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
      return res.status(503).json({ error: 'External service unavailable' });
    }

    res.status(500).json({ error: 'Internal server error' });
  }
}
