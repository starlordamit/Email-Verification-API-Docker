#!/bin/bash

# Nixpacks Deployment Script for Email Verification API
# This script helps deploy your app using Nixpacks

echo "🚀 Nixpacks Deployment Script for Email Verification API"
echo "========================================================"

# Check if nixpacks is installed
if ! command -v nixpacks &> /dev/null; then
    echo "❌ Nixpacks not found. Installing..."
    
    # Try to install nixpacks
    if command -v curl &> /dev/null; then
        echo "📦 Installing Nixpacks..."
        curl -sSL https://nixpacks.com/install.sh | bash
    else
        echo "❌ curl not found. Please install Nixpacks manually:"
        echo "   Visit: https://nixpacks.com/docs/install"
        exit 1
    fi
fi

echo "✅ Nixpacks found"

# Verify configuration files
echo "🔍 Verifying configuration files..."

if [ -f "nixpacks.toml" ]; then
    echo "✅ nixpacks.toml found"
else
    echo "❌ nixpacks.toml not found"
    exit 1
fi

if [ -f "requirements.txt" ]; then
    echo "✅ requirements.txt found"
else
    echo "❌ requirements.txt not found"
    exit 1
fi

if [ -f "app.py" ]; then
    echo "✅ app.py found"
else
    echo "❌ app.py not found"
    exit 1
fi

# Test nixpacks build locally
echo "🔧 Testing Nixpacks build..."
echo "Building with nixpacks..."

nixpacks build . --name email-verification-api

if [ $? -eq 0 ]; then
    echo "✅ Nixpacks build completed successfully"
else
    echo "❌ Nixpacks build failed"
    exit 1
fi

# Test the built image
echo "🧪 Testing the built container..."
echo "Starting container for testing..."

# Run the container in the background
docker run -d --name email-api-test -p 5000:5000 email-verification-api

# Wait for startup
echo "Waiting for container to start..."
sleep 10

# Test health endpoint
echo "Testing health endpoint..."
if curl -f http://localhost:5000/health >/dev/null 2>&1; then
    echo "✅ Health check passed - container is working!"
    echo "🎉 Nixpacks build and test successful!"
    echo ""
    echo "Your API is accessible at: http://localhost:5000"
    echo "Health check: http://localhost:5000/health"
    echo "API docs: http://localhost:5000/"
else
    echo "❌ Health check failed"
    echo "Checking container logs..."
    docker logs email-api-test
fi

# Cleanup test container
echo "🧹 Cleaning up test container..."
docker stop email-api-test >/dev/null 2>&1
docker rm email-api-test >/dev/null 2>&1

echo ""
echo "========================================================"
echo "✅ Local Nixpacks deployment test completed!"
echo ""
echo "📋 Next Steps for Cloud Deployment:"
echo "1. Push your code to GitHub/GitLab"
echo "2. Connect your repository to your cloud platform:"
echo "   • Railway: https://railway.app"
echo "   • Render: https://render.com"
echo "   • Heroku: https://heroku.com"
echo "   • Vercel: https://vercel.com"
echo ""
echo "3. Your platform should automatically detect and use:"
echo "   • nixpacks.toml (primary configuration)"
echo "   • Procfile (fallback)"
echo ""
echo "🔧 Environment Variables to Set:"
echo "   PORT=5000"
echo "   ENV=production"
echo "   REDIS_URL=<your-redis-url>"
echo "   API_KEY=<your-secure-api-key>"
echo "========================================================" 