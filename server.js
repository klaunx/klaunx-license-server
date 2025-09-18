const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const rateLimiter = new RateLimiterMemory({
    keyPrefix: 'license_validation',
    points: 10,
    duration: 60,
});

// Initialize SQLite database
const db = new sqlite3.Database('./licenses.db');

// Create tables
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            email TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            active BOOLEAN DEFAULT 1
        )
    `);
    
    // Insert demo licenses
    const demoLicenses = [
        ['KLAUNX-LIFETIME-DEMO01-ABCDEF', 'LIFETIME', 'demo@klaunx.com', null],
        ['KLAUNX-YEARLY-DEMO02-GHIJKL', 'YEARLY', 'demo@klaunx.com', new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()],
        ['KLAUNX-MONTHLY-DEMO03-MNOPQR', 'MONTHLY', 'demo@klaunx.com', new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()]
    ];
    
    demoLicenses.forEach(([key, type, email, expires]) => {
        db.run('INSERT OR IGNORE INTO licenses (key, type, email, expires_at) VALUES (?, ?, ?, ?)', [key, type, email, expires]);
    });
});

// Routes
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/api/validate-license', async (req, res) => {
    try {
        await rateLimiter.consume(req.ip);
        
        const { license_key } = req.body;
        
        if (!license_key) {
            return res.status(400).json({ valid: false, reason: 'missing_key' });
        }
        
        db.get('SELECT * FROM licenses WHERE key = ? AND active = 1', [license_key], (err, row) => {
            if (err) {
                return res.status(500).json({ valid: false, reason: 'server_error' });
            }
            
            if (!row) {
                return res.status(404).json({ valid: false, reason: 'not_found' });
            }
            
            // Check expiry
            if (row.type !== 'LIFETIME' && row.expires_at) {
                const expiryDate = new Date(row.expires_at);
                if (expiryDate < new Date()) {
                    return res.status(403).json({ valid: false, reason: 'expired' });
                }
            }
            
            res.json({
                valid: true,
                type: row.type,
                expires: row.expires_at,
                email: row.email
            });
        });
        
    } catch {
        res.status(429).json({ valid: false, reason: 'rate_limit' });
    }
});

// JWT Authentication middleware
function authenticateJWT(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const JWT_SECRET = process.env.JWT_SECRET || 'dev_local_secret_change_me';
    jwt.verify(token, JWT_SECRET, (err, payload) => {
        if (err) return res.status(401).json({ error: 'Invalid token' });
        req.user = payload;
        next();
    });
}

// Issue short-lived JWT after verifying license key
app.post('/api/auth/token', async (req, res) => {
    const { license_key, device_id } = req.body || {};
    if (!license_key || !device_id) {
        return res.status(400).json({ error: 'license_key and device_id are required' });
    }
    
    db.get('SELECT * FROM licenses WHERE key = ? AND active = 1', [license_key], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'server_error' });
        }
        if (!row) {
            return res.status(403).json({ error: 'invalid_license' });
        }
        if (row.type !== 'LIFETIME' && row.expires_at && new Date(row.expires_at) < new Date()) {
            return res.status(403).json({ error: 'expired' });
        }
        const JWT_SECRET = process.env.JWT_SECRET || 'dev_local_secret_change_me';
        const payload = { deviceId: device_id, licenseKey: license_key, type: row.type };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token, expires: Math.floor(Date.now() / 1000) + 3600 });
    });
});

// Analyze proxy endpoint (requires JWT)
app.post('/api/v1/analyze', authenticateJWT, async (req, res) => {
    // Optional: per-user rate limit
    try { 
        await rateLimiter.consume(req.user.deviceId || req.ip); 
    } catch { 
        return res.status(429).json({ error: 'rate_limit' }); 
    }

    const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
    if (!OPENAI_API_KEY) {
        return res.status(503).json({ error: { message: 'OPENAI_API_KEY not configured on server' } });
    }

    const body = req.body;
    try {
        const fetch = (await import('node-fetch')).default;
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`,
            },
            body: JSON.stringify(body),
        });
        const data = await response.json();
        return res.status(response.status).json(data);
    } catch (e) {
        return res.status(500).json({ error: { message: 'proxy_failed', details: String(e) } });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Klaunx AI License Server running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
});