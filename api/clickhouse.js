import axios from 'axios';

// Rate limiting map
const rateLimits = new Map();

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
}

function checkRateLimit(ip) {
  const now = Date.now();
  if (!rateLimits.has(ip)) rateLimits.set(ip, []);
  const requests = rateLimits.get(ip).filter(time => now - time < 60000); // 1 min
  if (requests.length >= 30) return false;
  requests.push(now);
  rateLimits.set(ip, requests);
  return true;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const clientIP = getClientIP(req);
  if (!checkRateLimit(clientIP)) {
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

    const allowedOrigin = 'https://dropbase.shop';
    const origin = req.headers.origin || req.headers.referer || '';
    if (!origin.startsWith(allowedOrigin) && process.env.NODE_ENV === 'production') {
      return res.status(403).json({ error: 'Forbidden: Invalid origin' });
    }

    // Fetch ClickHouse config from Pastebin (optional: you can also use env vars)
    const configResponse = await fetch('https://pastebin.com/raw/Cr51ac3q');
    if (!configResponse.ok) throw new Error('Failed to fetch config');
    const config = await configResponse.json();

    const { CLICKHOUSE_URL, CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD } = config;
    if (!CLICKHOUSE_URL || !CLICKHOUSE_USERNAME || !CLICKHOUSE_PASSWORD) {
      return res.status(500).json({ error: 'Missing ClickHouse config keys' });
    }

    const formattedQuery = query.includes('FORMAT') ? query : `${query} FORMAT JSON`;

    const response = await axios({
      url: CLICKHOUSE_URL,
      method: 'POST',
      data: formattedQuery,
      headers: { 'Content-Type': 'text/plain' },
      auth: { username: CLICKHOUSE_USERNAME, password: CLICKHOUSE_PASSWORD },
      timeout: 30000
    });

    res.status(200).json(response.data);

  } catch (err) {
    console.error('ClickHouse error:', err.message);
    res.status(500).json({ error: 'Database query failed' });
  }
}
