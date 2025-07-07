#!/bin/bash

# Docker Rebuild Script - Fix "No module named 'main'" Error
# This script completely rebuilds the Docker container from scratch

echo "🔧 Docker Rebuild Script for Email Verification API"
echo "=================================================="

# Step 1: Update .env file with correct configuration
echo "📝 Step 1: Updating .env configuration..."
cat > .env << EOF
# Email Verification API - Docker Configuration
PORT=5000
ENV=production
DEBUG=false
LOG_LEVEL=INFO
LOG_FORMAT=json

# Redis Configuration  
REDIS_URL=redis://redis:6379/0
RATE_LIMIT_STORAGE=redis://redis:6379/1

# Security (optional for development)
REQUIRE_AUTH=false
API_KEY=dev-api-key-123

# Monitoring
ENABLE_SWAGGER=true
METRICS_ENABLED=true
EOF

echo "✅ .env file updated"

# Step 2: Clean up Docker cache and containers
echo "🧹 Step 2: Cleaning up Docker cache..."
echo "Stopping any running containers..."
docker-compose down --volumes --remove-orphans 2>/dev/null || true

echo "Removing Docker cache and unused images..."
docker system prune -f --volumes 2>/dev/null || true
docker builder prune -f 2>/dev/null || true

echo "✅ Docker cleanup completed"

# Step 3: Verify source files are correct
echo "🔍 Step 3: Verifying source files..."

# Check that app.py has the correct module-level app definition
if grep -q "^app = create_app()" app.py; then
    echo "✅ app.py has correct module-level app definition"
else
    echo "❌ ERROR: app.py missing module-level app definition"
    echo "Please ensure app.py contains 'app = create_app()' at module level"
    exit 1
fi

# Check Dockerfile CMD line
if grep -q 'CMD.*"app:app"' Dockerfile; then
    echo "✅ Dockerfile has correct CMD with app:app"
else
    echo "❌ ERROR: Dockerfile CMD line incorrect"
    echo "Please ensure Dockerfile CMD uses 'app:app' not 'main:app'"
    exit 1
fi

echo "✅ Source files verified"

# Step 4: Build new Docker image
echo "🏗️  Step 4: Building Docker image from scratch..."
echo "Building with --no-cache to ensure fresh build..."

docker-compose build --no-cache --pull

if [ $? -eq 0 ]; then
    echo "✅ Docker build completed successfully"
else
    echo "❌ Docker build failed"
    exit 1
fi

# Step 5: Test the container
echo "🧪 Step 5: Testing the container..."
echo "Starting container in background..."

docker-compose up -d

# Wait for container to start
echo "Waiting for container to start..."
sleep 10

# Test health endpoint
echo "Testing health endpoint..."
if curl -f http://localhost:8000/health >/dev/null 2>&1; then
    echo "✅ Health check passed - container is working!"
    echo "🎉 Docker rebuild successful!"
    echo ""
    echo "Your API is now running at: http://localhost:8000"
    echo "Health check: http://localhost:8000/health"
    echo "API docs: http://localhost:8000/"
else
    echo "❌ Health check failed"
    echo "Checking container logs..."
    docker-compose logs email-api
    exit 1
fi

echo ""
echo "=================================================="
echo "✅ Docker rebuild completed successfully!"
echo "The 'No module named main' error should now be fixed."
echo ""
echo "To stop the container: docker-compose down"
echo "To view logs: docker-compose logs -f email-api"
echo "==================================================" 