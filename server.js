const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Serve static files for admin dashboard
app.use(express.static('public'));

// Root route to serve dashboard
app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Klaunx AI - Admin Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 20px; padding: 30px; margin-bottom: 30px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); text-align: center; }
        .header h1 { font-size: 2.5em; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 10px; }
        .auth-section { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 20px; padding: 40px; text-align: center; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); }
        .auth-section input { width: 300px; padding: 15px; border: 2px solid #e1e5e9; border-radius: 10px; font-size: 16px; margin: 10px; }
        .auth-section button { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 15px 30px; border-radius: 10px; font-size: 16px; cursor: pointer; margin: 10px; }
        .dashboard { display: none; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 15px; padding: 25px; text-align: center; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1); }
        .stat-number { font-size: 2.5em; font-weight: bold; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 10px; }
        .stat-label { color: #666; font-size: 1.1em; }
        .users-table { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 20px; padding: 30px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #e1e5e9; }
        th { background: linear-gradient(135deg, #667eea, #764ba2); color: white; font-weight: 600; }
        .license-type { padding: 5px 10px; border-radius: 20px; font-size: 0.9em; font-weight: bold; }
        .license-lifetime { background: #e8f5e8; color: #2d7d32; }
        .license-yearly { background: #fff3e0; color: #f57c00; }
        .license-monthly { background: #e3f2fd; color: #1976d2; }
        .error { background: #ffebee; color: #c62828; padding: 15px; border-radius: 10px; margin: 20px 0; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Klaunx AI Admin Dashboard</h1>
            <p>Monitor user activity, track usage, and manage licenses</p>
        </div>
        
        <div id="auth-section" class="auth-section">
            <h2>🔐 Admin Authentication</h2>
            <div>
                <input type="password" id="admin-key" placeholder="Enter Admin Key" />
                <br>
                <button onclick="authenticate()">Access Dashboard</button>
            </div>
            <div id="auth-error" class="error" style="display: none;"></div>
        </div>
        
        <div id="dashboard" class="dashboard">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number" id="total-users">-</div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="total-requests">-</div>
                    <div class="stat-label">Total Requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="total-tokens">-</div>
                    <div class="stat-label">Tokens Used</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="total-cost">-</div>
                    <div class="stat-label">Total Cost</div>
                </div>
            </div>
            
            <div class="users-table">
                <h3>👥 User Management</h3>
                <table id="users-table">
                    <thead>
                        <tr>
                            <th>License Key</th>
                            <th>Type</th>
                            <th>Email</th>
                            <th>Requests</th>
                            <th>Tokens</th>
                            <th>Cost</th>
                            <th>Last Used</th>
                        </tr>
                    </thead>
                    <tbody id="users-tbody">
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script>
        let adminKey = '';
        
        function authenticate() {
            adminKey = document.getElementById('admin-key').value;
            if (!adminKey) {
                showError('Please enter admin key');
                return;
            }
            
            fetch('/api/admin/usage', {
                headers: { 'x-admin-key': adminKey }
            })
            .then(response => {
                if (response.status === 401) {
                    throw new Error('Invalid admin key');
                }
                return response.json();
            })
            .then(data => {
                document.getElementById('auth-section').style.display = 'none';
                document.getElementById('dashboard').style.display = 'block';
                loadDashboard();
            })
            .catch(error => {
                showError(error.message);
            });
        }
        
        function showError(message) {
            const errorEl = document.getElementById('auth-error');
            errorEl.textContent = message;
            errorEl.style.display = 'block';
            setTimeout(() => errorEl.style.display = 'none', 3000);
        }
        
        async function loadDashboard() {
            try {
                const response = await fetch('/api/admin/usage', {
                    headers: { 'x-admin-key': adminKey }
                });
                const data = await response.json();
                
                updateStats(data.licenses);
                updateUsersTable(data.licenses);
            } catch (error) {
                console.error('Failed to load dashboard:', error);
            }
        }
        
        function updateStats(licenses) {
            const totalUsers = licenses.length;
            const totalRequests = licenses.reduce((sum, l) => sum + (l.total_requests || 0), 0);
            const totalTokens = licenses.reduce((sum, l) => sum + (l.total_tokens || 0), 0);
            const totalCost = licenses.reduce((sum, l) => sum + (l.total_cost || 0), 0);
            
            document.getElementById('total-users').textContent = totalUsers;
            document.getElementById('total-requests').textContent = totalRequests.toLocaleString();
            document.getElementById('total-tokens').textContent = totalTokens.toLocaleString();
            document.getElementById('total-cost').textContent = '$' + totalCost.toFixed(2);
        }
        
        function updateUsersTable(licenses) {
            const tbody = document.getElementById('users-tbody');
            tbody.innerHTML = '';
            
            licenses.forEach(license => {
                const row = document.createElement('tr');
                const lastUsed = license.last_used ? 
                    new Date(license.last_used).toLocaleDateString() : 'Never';
                
                row.innerHTML = \`
                    <td><code>\${license.key.substring(0, 20)}...</code></td>
                    <td><span class="license-type license-\${license.type.toLowerCase()}">\${license.type}</span></td>
                    <td>\${license.email || 'N/A'}</td>
                    <td>\${license.total_requests || 0}</td>
                    <td>\${(license.total_tokens || 0).toLocaleString()}</td>
                    <td>$\${(license.total_cost || 0).toFixed(4)}</td>
                    <td>\${lastUsed}</td>
                \`;
                tbody.appendChild(row);
            });
        }
        
        document.getElementById('admin-key').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                authenticate();
            }
        });
        
        // Auto-refresh every 30 seconds
        setInterval(() => {
            if (adminKey && document.getElementById('dashboard').style.display !== 'none') {
                loadDashboard();
            }
        }, 30000);
    </script>
</body>
</html>
    `);
});

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
    
    // Usage tracking table
    db.run(`
        CREATE TABLE IF NOT EXISTS usage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            device_id TEXT NOT NULL,
            request_type TEXT NOT NULL,
            tokens_used INTEGER DEFAULT 0,
            cost_usd DECIMAL(10,6) DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (license_key) REFERENCES licenses(key)
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
    const startTime = Date.now();
    
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
        
        // Track usage after successful request
        if (response.ok && data.usage) {
            const tokensUsed = data.usage.total_tokens || 0;
            const estimatedCost = calculateCost(body.model || 'gpt-4o-mini', tokensUsed);
            
            // Log usage to database
            db.run(`
                INSERT INTO usage_logs (license_key, device_id, request_type, tokens_used, cost_usd)
                VALUES (?, ?, ?, ?, ?)
            `, [req.user.licenseKey, req.user.deviceId, 'ai_analysis', tokensUsed, estimatedCost], (err) => {
                if (err) console.error('❌ Failed to log usage:', err);
                else console.log(`📊 Logged usage: ${req.user.licenseKey} used ${tokensUsed} tokens ($${estimatedCost.toFixed(4)})`);
            });
        }
        
        return res.status(response.status).json(data);
    } catch (e) {
        return res.status(500).json({ error: { message: 'proxy_failed', details: String(e) } });
    }
});

// Usage analytics endpoint
app.get('/api/usage/:license_key', async (req, res) => {
    const { license_key } = req.params;
    
    try {
        await rateLimiter.consume(req.ip);
    } catch {
        return res.status(429).json({ error: 'rate_limit' });
    }
    
    // Get usage stats for the license
    db.all(`
        SELECT 
            COUNT(*) as total_requests,
            SUM(tokens_used) as total_tokens,
            SUM(cost_usd) as total_cost,
            DATE(timestamp) as date,
            COUNT(*) as daily_requests
        FROM usage_logs 
        WHERE license_key = ? 
        AND timestamp >= datetime('now', '-30 days')
        GROUP BY DATE(timestamp)
        ORDER BY date DESC
    `, [license_key], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'database_error' });
        }
        
        // Get overall stats
        db.get(`
            SELECT 
                COUNT(*) as total_requests,
                SUM(tokens_used) as total_tokens,
                SUM(cost_usd) as total_cost
            FROM usage_logs 
            WHERE license_key = ?
        `, [license_key], (err, totals) => {
            if (err) {
                return res.status(500).json({ error: 'database_error' });
            }
            
            res.json({
                license_key,
                overall: totals || { total_requests: 0, total_tokens: 0, total_cost: 0 },
                daily_usage: rows || []
            });
        });
    });
});

// Admin endpoint to see all usage
app.get('/api/admin/usage', async (req, res) => {
    const adminKey = req.headers['x-admin-key'];
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(401).json({ error: 'unauthorized' });
    }
    
    db.all(`
        SELECT 
            l.key,
            l.type,
            l.email,
            l.created_at,
            l.expires_at,
            l.active,
            COUNT(u.id) as total_requests,
            SUM(u.tokens_used) as total_tokens,
            SUM(u.cost_usd) as total_cost,
            MAX(u.timestamp) as last_used
        FROM licenses l
        LEFT JOIN usage_logs u ON l.key = u.license_key
        GROUP BY l.key
        ORDER BY total_requests DESC
    `, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'database_error' });
        }
        res.json({ 
            licenses: rows || [],
            server_stats: {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                timestamp: new Date().toISOString()
            }
        });
    });
});

// Admin endpoint for daily analytics
app.get('/api/admin/analytics', async (req, res) => {
    const adminKey = req.headers['x-admin-key'];
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(401).json({ error: 'unauthorized' });
    }
    
    db.all(`
        SELECT 
            DATE(timestamp) as date,
            COUNT(*) as requests,
            SUM(tokens_used) as tokens,
            SUM(cost_usd) as cost,
            COUNT(DISTINCT license_key) as active_users
        FROM usage_logs 
        WHERE timestamp >= datetime('now', '-30 days')
        GROUP BY DATE(timestamp)
        ORDER BY date DESC
    `, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'database_error' });
        }
        res.json({ daily_analytics: rows || [] });
    });
});

// Admin endpoint to manage licenses
app.post('/api/admin/license/:action', async (req, res) => {
    const adminKey = req.headers['x-admin-key'];
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(401).json({ error: 'unauthorized' });
    }
    
    const { action } = req.params;
    const { license_key, type, email, expires_at } = req.body;
    
    switch (action) {
        case 'create':
            db.run('INSERT INTO licenses (key, type, email, expires_at) VALUES (?, ?, ?, ?)', 
                [license_key, type, email, expires_at], function(err) {
                if (err) {
                    return res.status(400).json({ error: 'License already exists or invalid data' });
                }
                res.json({ success: true, id: this.lastID });
            });
            break;
            
        case 'deactivate':
            db.run('UPDATE licenses SET active = 0 WHERE key = ?', [license_key], function(err) {
                if (err) {
                    return res.status(500).json({ error: 'database_error' });
                }
                res.json({ success: true, changes: this.changes });
            });
            break;
            
        case 'activate':
            db.run('UPDATE licenses SET active = 1 WHERE key = ?', [license_key], function(err) {
                if (err) {
                    return res.status(500).json({ error: 'database_error' });
                }
                res.json({ success: true, changes: this.changes });
            });
            break;
            
        default:
            res.status(400).json({ error: 'Invalid action' });
    }
});

// Cost calculation helper
function calculateCost(model, tokens) {
    const pricing = {
        'gpt-4o': { input: 0.0025, output: 0.01 }, // per 1K tokens
        'gpt-4o-mini': { input: 0.000150, output: 0.0006 },
        'gpt-4': { input: 0.03, output: 0.06 },
        'gpt-3.5-turbo': { input: 0.0015, output: 0.002 }
    };
    
    const modelPricing = pricing[model] || pricing['gpt-4o-mini'];
    // Simplified: assume 50/50 input/output split
    return (tokens / 1000) * ((modelPricing.input + modelPricing.output) / 2);
}

app.listen(PORT, () => {
    console.log(`🚀 Klaunx AI License Server running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
});