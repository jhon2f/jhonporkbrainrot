// api/lookup.js
import rateLimit from 'express-rate-limit'; // Optional: we implement manual limiter here
import fetch from 'node-fetch';

const rateLimits = new Map();

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
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    clearTimeout(timeout);
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
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

// Serverless handler
export default async function handler(req, res) {
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';

  if (req.method === 'GET' && req.url.endsWith('/health')) {
    return res.status(200).json({
      status: 'operational',
      supported_types: ['email', 'username', 'phone', 'ip', 'domain']
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!checkRateLimit(clientIP)) {
    return res.status(429).json({ error: 'Rate limit exceeded' });
  }

  try {
    const body = await new Promise((resolve, reject) => {
      let data = '';
      req.on('data', chunk => data += chunk);
      req.on('end', () => resolve(JSON.parse(data)));
      req.on('error', reject);
    });

    const { query, type } = body;
    if (!query || query.length < 2 || query.length > 1000) {
      return res.status(400).json({ error: 'Invalid query' });
    }

    let results;
    let searchType = type;

    if (type === 'idleak') {
      const params = JSON.parse(query);
      results = await queryIdLeak(params);
      searchType = 'idleak';
    } else {
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

    if (err.name === 'AbortError') return res.status(408).json({ error: 'Request timeout' });
    if (err.message.includes('HTTP') || err.code === 'ENOTFOUND') return res.status(503).json({ error: 'Service unavailable' });

    res.status(500).json({ error: 'Internal error' });
  }
}
