import fs from 'fs';
import path from 'path';
import axios from 'axios';
import crypto from 'crypto';

// In-memory maps for rate limiting and sessions
const rateLimits = new Map();
const authRateLimits = new Map();
const sessions = new Map();

// ----------------------- Helper Functions -----------------------

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
}

// Rate limiting
function checkRateLimit(map, ip, limit, windowMs) {
  const now = Date.now();
  if (!map.has(ip)) map.set(ip, []);
  const requests = map.get(ip).filter(time => now - time < windowMs);
  if (requests.length >= limit) return false;
  requests.push(now);
  map.set(ip, requests);
  return true;
}

// Generate session token
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Validate session
function validateSession(req) {
  const token = req.headers['x-session-token'];
  if (!token) throw new Error('No token provided');

  const session = sessions.get(token);
  if (!session) throw new Error('Invalid session');

  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    throw new Error('Session expired');
  }

  if (session.requestCount >= session.maxRequests) throw new Error('Rate limit exceeded');

  session.requestCount++;
  sessions.set(token, session);
  return session;
}

// Cleanup expired sessions
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (session.expiresAt < now) sessions.delete(id);
  }
}, 60000);

// ----------------------- Serverless Handler -----------------------

export default async function handler(req, res) {
  const clientIP = getClientIP(req);

  // Serve index.html
  if (req.method === 'GET' && req.url === '/') {
    const filePath = path.join(process.cwd(), 'public', 'index.html');
    const html = fs.readFileSync(filePath, 'utf8');
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(html);
  }

  // ----------------------- AUTH Endpoint -----------------------
  if (req.method === 'POST' && req.url === '/api/auth') {
    if (!checkRateLimit(authRateLimits, clientIP, 10, 15 * 60 * 1000)) {
      return res.status(429).json({ error: 'Too many auth attempts' });
    }

    try {
      const sessionId = generateToken();
      const sessionData = {
        ip: clientIP,
        timestamp: Date.now(),
        expiresAt: Date.now() + 30 * 60 * 1000, // 30 min
        requestCount: 0,
        maxRequests: 200
      };
      sessions.set(sessionId, sessionData);

      return res.status(200).json({ token: sessionId, expiresIn: 1800, requestLimit: 200 });
    } catch (err) {
      return res.status(500).json({ error: 'Auth failed' });
    }
  }

  // ----------------------- LOOKUP Endpoint -----------------------
  if (req.method === 'POST' && req.url === '/api/lookup') {
    try {
      const body = await new Promise((resolve, reject) => {
        let data = '';
        req.on('data', chunk => data += chunk);
        req.on('end', () => resolve(JSON.parse(data)));
        req.on('error', reject);
      });

      validateSession(req); // check session

      const { query, type } = body;
      if (!query || query.length < 2 || query.length > 1000) {
        return res.status(400).json({ error: 'Invalid query' });
      }

      // Example: call OSINT API (replace with your existing logic)
      const response = await axios.post('https://osintdog.com/api/search', {
        field: [{ [type || 'username']: query }]
      }, {
        headers: { 'X-API-Key': process.env.API_KEY, 'Content-Type': 'application/json' },
        timeout: 30000
      });

      return res.status(200).json({
        success: true,
        search_term: query,
        search_type: type || 'username',
        investigation_results: response.data,
        timestamp: new Date().toISOString()
      });

    } catch (err) {
      console.error('Lookup error:', err.message);
      if (err.name === 'AbortError') return res.status(408).json({ error: 'Request timeout' });
      return res.status(500).json({ error: 'Internal error' });
    }
  }

  // ----------------------- CLICKHOUSE Endpoint -----------------------
  if (req.method === 'POST' && req.url === '/api/clickhouse') {
    if (!checkRateLimit(rateLimits, clientIP, 30, 60 * 1000)) {
      return res.status(429).json({ error: 'Too many requests' });
    }

    try {
      const body = await new Promise((resolve, reject) => {
        let data = '';
        req.on('data', chunk => data += chunk);
        req.on('end', () => resolve(JSON.parse(data)));
        req.on('error', reject);
      });

      const { query } = body;
      if (!query) return res.status(400).json({ error: 'Query is required' });

      // Fetch config from Pastebin
      const configResponse = await fetch('https://pastebin.com/raw/Cr51ac3q');
      if (!configResponse.ok) throw new Error('Failed to fetch config');
      const { CLICKHOUSE_URL, CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD } = await configResponse.json();

      const formattedQuery = query.includes('FORMAT') ? query : `${query} FORMAT JSON`;

      const response = await axios({
        url: CLICKHOUSE_URL,
        method: 'POST',
        data: formattedQuery,
        headers: { 'Content-Type': 'text/plain' },
        auth: { username: CLICKHOUSE_USERNAME, password: CLICKHOUSE_PASSWORD },
        timeout: 30000
      });

      return res.status(200).json(response.data);

    } catch (err) {
      console.error('ClickHouse error:', err.message);
      return res.status(500).json({ error: 'Database query failed' });
    }
  }

  // Method not allowed
  res.status(405).json({ error: 'Method not allowed' });
}
