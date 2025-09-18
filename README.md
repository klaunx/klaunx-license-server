# Klaunx AI License Server

Simple, secure license validation server for Klaunx AI direct sales.

## Quick Deploy Options

### Option 1: Railway (Recommended - Free Tier)
1. Push this folder to GitHub
2. Connect Railway to your GitHub repo
3. Deploy automatically with zero config
4. Get free HTTPS domain: `your-app.railway.app`

### Option 2: Vercel (Serverless)
1. Install Vercel CLI: `npm i -g vercel`
2. Run `vercel` in this directory
3. Deploy with automatic HTTPS

### Option 3: DigitalOcean App Platform
1. Connect GitHub repo
2. Auto-deploy with managed database
3. $5/month for basic tier

### Option 4: Heroku
1. `heroku create klaunx-license-server`
2. `git push heroku main`
3. Automatic HTTPS and scaling

## Local Development

```bash
# Install dependencies
npm install

# Copy environment file
cp env.example .env

# Edit .env with your settings
nano .env

# Start development server
npm run dev

# Test health check
curl http://localhost:3000/health
```

## API Endpoints

### License Validation
```bash
POST /api/validate-license
Content-Type: application/json

{
  "license_key": "KLAUNX-LIFETIME-DEMO01-ABCDEF"
}

# Response:
{
  "valid": true,
  "type": "LIFETIME",
  "expires": null,
  "email": "demo@klaunx.com"
}
```

### Generate License (Admin)
```bash
POST /api/generate-license
Content-Type: application/json

{
  "type": "YEARLY",
  "email": "customer@example.com",
  "admin_key": "your_admin_key"
}

# Response:
{
  "license_key": "KLAUNX-YEARLY-A1B2C3-D4E5F6",
  "type": "YEARLY",
  "email": "customer@example.com",
  "expires": "2025-09-16T10:58:00.000Z"
}
```

### Statistics (Admin)
```bash
GET /api/stats?admin_key=your_admin_key

# Response:
{
  "license_stats": [
    {"type": "LIFETIME", "count": 5, "active_count": 5},
    {"type": "YEARLY", "count": 12, "active_count": 10}
  ],
  "validation_stats": {
    "total_validations": 150,
    "successful_validations": 142
  }
}
```

## Demo License Keys (for testing)

```
KLAUNX-LIFETIME-DEMO01-ABCDEF
KLAUNX-YEARLY-DEMO02-GHIJKL
KLAUNX-MONTHLY-DEMO03-MNOPQR
```

## Gumroad Integration

Add webhook to automatically create licenses:

```javascript
app.post('/webhook/gumroad', (req, res) => {
    // Verify webhook signature
    // Create license for customer
    // Send license key via email
});
```

## Security Features

- ✅ Rate limiting (10 requests/minute)
- ✅ CORS protection
- ✅ Helmet security headers
- ✅ Request logging
- ✅ Input validation
- ✅ SQL injection protection
- ✅ Admin key authentication

## Production Checklist

- [ ] Change ADMIN_KEY in .env
- [ ] Set proper ALLOWED_ORIGINS
- [ ] Configure HTTPS (automatic on most platforms)
- [ ] Set up monitoring/alerts
- [ ] Configure backups for database
- [ ] Add email notifications for new licenses
- [ ] Set up domain (optional)

## Update App URLs

After deployment, update these URLs in your Klaunx AI app:

```swift
// In LicenseManager.validateWithServer()
let url = URL(string: "https://your-domain.railway.app/api/validate-license")

// In Settings purchase button
NSWorkspace.shared.open(URL(string: "https://your-gumroad.com/l/klaunx")!)
```

## Cost Estimate

- **Railway Free Tier**: $0/month (500 hours)
- **Railway Pro**: $5/month (unlimited)
- **Domain (optional)**: $10-15/year
- **Total**: ~$5-10/month for thousands of users

Much cheaper than App Store infrastructure!
