const rateLimits = new Map();

// Get client IP
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.headers['cf-connecting-ip'] ||
         req.socket.remoteAddress || 
         req.connection.remoteAddress ||
         'unknown';
}

// Rate limiter
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
  // Set CORS headers - enhanced for Cloudflare
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, CF-Connecting-IP, CF-Ray');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { query } = req.body;
    if (!query) {
      return res.status(400).json({ error: 'Query is required' });
    }

    const clientIP = getIP(req);

    // Rate limiting per IP
    if (!checkRateLimit(clientIP)) {
      return res.status(429).json({ error: 'Too many requests' });
    }

    // Origin check for production - include Cloudflare domain
    const allowedOrigins = [
      'https://dropbase.shop', 
      'https://your-app.vercel.app',
      'https://www.dropbase.shop'  // Add www version if using Cloudflare
    ];
    const origin = req.headers['origin'] || req.headers['referer'] || '';
    
    // Skip origin check in development or if no origin header
    if (process.env.NODE_ENV === 'production' && origin) {
      const isAllowed = allowedOrigins.some(allowed => 
        origin.startsWith(allowed) || origin.replace('www.', '').startsWith(allowed.replace('www.', ''))
      );
      if (!isAllowed) {
        console.log(`Origin check failed. Origin: ${origin}, Allowed: ${allowedOrigins.join(', ')}`);
        return res.status(403).json({ error: 'Forbidden: Invalid origin' });
      }
    }

    // Fetch config from Pastebin
    let config;
    try {
      const configResponse = await fetch("https://pastebin.com/raw/Cr51ac3q");
      if (!configResponse.ok) {
        throw new Error(`Failed to fetch config: ${configResponse.status}`);
      }
      config = await configResponse.json();
    } catch (err) {
      console.error('Config fetch error:', err.message);
      return res.status(500).json({ error: 'Failed to fetch database configuration' });
    }

    const { CLICKHOUSE_URL, CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD } = config;
    
    if (!CLICKHOUSE_URL || !CLICKHOUSE_USERNAME || !CLICKHOUSE_PASSWORD) {
      return res.status(500).json({ error: 'Incomplete database configuration' });
    }

    // Format query
    const formattedQuery = query.includes('FORMAT') ? query : `${query} FORMAT JSON`;

    // Execute ClickHouse query
    const response = await fetch(CLICKHOUSE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Authorization': 'Basic ' + Buffer.from(`${CLICKHOUSE_USERNAME}:${CLICKHOUSE_PASSWORD}`).toString('base64')
      },
      body: formattedQuery,
      signal: AbortSignal.timeout(30000) // 30 second timeout
    });

    if (!response.ok) {
      throw new Error(`ClickHouse HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    res.json(data);

} catch (error) {
    console.error('ClickHouse error:', error.message);
    
    if (error.name === 'AbortError' || error.message.includes('timeout')) {
        return res.status(408).json({ error: 'Database query timeout' });
    }
    
    if (error.message.includes('HTTP')) {
        return res.status(503).json({ error: 'Database service unavailable' });
    }
    
    // Fetch server IP and include in the 500 response
    try {
    
        res.status(500).json({ 
            error: 'Database query failed',
        });
    } catch {
        res.status(500).json({ 
            error: 'Database query failed',
            serverIp: 'Unknown'
        });
    }
}

