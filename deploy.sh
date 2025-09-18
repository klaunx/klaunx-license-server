#!/bin/bash

echo "🚀 Klaunx AI License Server Deployment Script"
echo "============================================="

# Check if we're in the right directory
if [ ! -f "server.js" ]; then
    echo "❌ Error: server.js not found. Run this script from the server directory."
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚙️ Creating .env file from template..."
    cp env.example .env
    echo "📝 Please edit .env file with your settings:"
    echo "   - ADMIN_KEY (change from default)"
    echo "   - ALLOWED_ORIGINS (your domain)"
    echo "   - Other optional settings"
    echo ""
    read -p "Press Enter when you've configured .env..."
fi

# Test the server locally
echo "🧪 Testing server locally..."
timeout 5s npm start &
SERVER_PID=$!
sleep 2

# Test health endpoint
HEALTH_CHECK=$(curl -s http://localhost:3000/health 2>/dev/null || echo "failed")
if [[ $HEALTH_CHECK == *"ok"* ]]; then
    echo "✅ Local server test passed"
else
    echo "❌ Local server test failed"
fi

# Kill test server
kill $SERVER_PID 2>/dev/null

echo ""
echo "🌐 Ready to deploy! Choose your platform:"
echo ""
echo "1. Railway (Recommended - Free tier available)"
echo "   - Push to GitHub"
echo "   - Connect Railway to your repo"
echo "   - Deploy automatically"
echo ""
echo "2. Vercel (Serverless)"
echo "   - npm i -g vercel"
echo "   - vercel"
echo ""
echo "3. Heroku"
echo "   - heroku create klaunx-license-server"
echo "   - git push heroku main"
echo ""
echo "4. DigitalOcean App Platform"
echo "   - Connect GitHub repo"
echo "   - Auto-deploy with managed database"
echo ""

read -p "Which platform would you like instructions for? (1-4): " PLATFORM

case $PLATFORM in
    1)
        echo ""
        echo "🚂 Railway Deployment:"
        echo "1. Go to https://railway.app"
        echo "2. Sign in with GitHub"
        echo "3. Click 'New Project' > 'Deploy from GitHub repo'"
        echo "4. Select your repo and the /server folder"
        echo "5. Add environment variables from your .env file"
        echo "6. Deploy! You'll get a URL like: https://your-app.railway.app"
        ;;
    2)
        echo ""
        echo "▲ Vercel Deployment:"
        echo "1. npm i -g vercel"
        echo "2. vercel login"
        echo "3. vercel"
        echo "4. Follow prompts"
        echo "5. Add environment variables in Vercel dashboard"
        ;;
    3)
        echo ""
        echo "🟣 Heroku Deployment:"
        echo "1. heroku login"
        echo "2. heroku create klaunx-license-server"
        echo "3. heroku config:set ADMIN_KEY=your_key"
        echo "4. git push heroku main"
        ;;
    4)
        echo ""
        echo "🌊 DigitalOcean Deployment:"
        echo "1. Go to cloud.digitalocean.com"
        echo "2. Create App Platform project"
        echo "3. Connect GitHub repo"
        echo "4. Select /server folder"
        echo "5. Add environment variables"
        ;;
esac

echo ""
echo "📱 After deployment, update your Klaunx AI app:"
echo "1. Replace 'https://your-server.com' with your actual server URL"
echo "2. Update purchase URL to your Gumroad store"
echo "3. Test with demo license keys"
echo ""
echo "✅ Your license server is ready to deploy!"


