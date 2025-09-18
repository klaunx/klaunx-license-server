const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const { RateLimiterMemory } = require('rate-limiter-flexible');
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

app.listen(PORT, () => {
    console.log(`🚀 Klaunx AI License Server running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
});
