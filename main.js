const express = require('express');
const path = require('path');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const rateLimits = new Map();

// Middleware
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Get client IP
app.use((req, res, next) => {
  req.clientIP = req.headers['cf-connecting-ip'] ||
                 req.headers['x-forwarded-for']?.split(',')[0] ||
                 req.connection.remoteAddress ||
                 req.socket.remoteAddress ||
                 req.ip ||
                 'unknown';
  next();
});

// Routes
app.use('/api/auth', require('./api/auth'));
app.use('/api/lookup', require('./api/lookup'));

// ClickHouse endpoint
app.post('/api/clickhouse', async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: 'Query is required' });

    const clientIP = req.clientIP;
    const allowedOrigin = 'https://dropbase.shop';
    const origin = req.get('origin') || req.get('referer') || '';

    if (!origin.startsWith(allowedOrigin) && process.env.NODE_ENV === 'production') {
      return res.status(403).json({ error: 'Forbidden: Invalid origin' });
    }

    // Rate limiting per IP
    const now = Date.now();
    if (!rateLimits.has(clientIP)) rateLimits.set(clientIP, []);
    const requests = rateLimits.get(clientIP).filter(time => now - time < 60000); // 1 min
    if (requests.length >= 30) return res.status(429).json({ error: 'Too many requests' });
    requests.push(now);
    rateLimits.set(clientIP, requests);

    // Fetch config from Pastebin
    const configResponse = await fetch("https://pastebin.com/raw/Cr51ac3q");
    if (!configResponse.ok) return res.status(500).json({ error: 'Failed to fetch config' });
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

    res.json(response.data);
  } catch (error) {
    console.error('ClickHouse error:', error.message);
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
