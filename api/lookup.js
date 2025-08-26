const express = require('express');
const rateLimit = require('express-rate-limit');
const auth = require('./auth');
const router = express.Router();

const lookupLimiter = rateLimit({
  windowMs: 2 * 60 * 1000,
  max: 15,
  message: { error: 'Rate limit exceeded' }
});

function detectType(term) {
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(term)) return "email";
  if (/^[\+]?[1-9][\d\s\-\(\)]{7,15}$/.test(term)) return "phone";
  if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(term)) return "ip";
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(term) && !term.startsWith('http')) return "domain";
  return "username";
}

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
  } catch (error) {
    clearTimeout(timeout);
    throw error;
  }
}

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
  } catch (error) {
    clearTimeout(timeout);
    throw error;
  }
}

router.use(lookupLimiter);

router.post('/', async (req, res) => {
  try {
    auth.validateSession(req);
    
    const { query, type } = req.body;
    if (!query || query.length < 2 || query.length > 1000) {
      return res.status(400).json({ error: 'Invalid query' });
    }
    
    let results;
    let searchType = type;
    
    if (type === 'idleak') {
      // Parse the JSON query for IdLeak parameters
      const params = JSON.parse(query);
      results = await queryIdLeak(params);
      searchType = 'idleak';
    } else {
      // Handle OSINT queries
      const sanitized = query.replace(/[<>"'\x00-\x1f\x7f-\x9f]/g, '').trim();
      searchType = type === 'keyword' ? 'username' : (type || detectType(sanitized));
      results = await queryOSINT(sanitized, searchType);
    }
    
    res.json({
      success: true,
      search_term: type === 'idleak' ? 'idleak_search' : query,
      search_type: searchType,
      investigation_results: results,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Lookup error:', error.message);
    
    if (error.message.includes('timeout')) {
      return res.status(408).json({ error: 'Request timeout' });
    }
    
    if (error.message.includes('HTTP') || error.code === 'ENOTFOUND') {
      return res.status(503).json({ error: 'Service unavailable' });
    }
    
    res.status(500).json({ error: 'Internal error' });
  }
});

router.get('/health', (req, res) => {
  res.json({
    status: 'operational',
    supported_types: ['email', 'username', 'phone', 'ip', 'domain']
  });
});

module.exports = router;