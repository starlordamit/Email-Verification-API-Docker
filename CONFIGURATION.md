# Email Verification API - Configuration Guide

This guide covers all configuration options for the Email Verification API v2.0.

## 📋 Table of Contents

- [Quick Setup](#quick-setup)
- [Environment Variables](#environment-variables)
- [Configuration Profiles](#configuration-profiles)
- [Security Configuration](#security-configuration)
- [Performance Tuning](#performance-tuning)
- [Monitoring Setup](#monitoring-setup)
- [Production Checklist](#production-checklist)

## ⚡ Quick Setup

### Development (Default)
```bash
# Minimal setup - API works out of the box
python app.py
```

### Production
```bash
# Create .env file
cat > .env << EOF
ENV=production
API_KEY=your-secure-api-key-here

REQUIRE_AUTH=true
REDIS_URL=redis://localhost:6379/0
EOF

python app.py
```

## 🔧 Environment Variables

### Application Settings

| Variable | Default | Description | Required |
|----------|---------|-------------|----------|
| `ENV` | `development` | Environment mode (`development`/`production`) | No |
| `DEBUG` | `false` | Enable debug mode and verbose logging | No |
| `HOST` | `0.0.0.0` | Server bind address | No |
| `PORT` | `5004` | Server port number | No |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`/`INFO`/`WARNING`/`ERROR`) | No |

**Example:**
```bash
ENV=production
DEBUG=false
HOST=0.0.0.0
PORT=5004
LOG_LEVEL=INFO
```

### Security & Authentication

| Variable | Default | Description | Required |
|----------|---------|-------------|----------|
| `API_KEY` | `""` | Primary API key for authentication | Production |
| `REQUIRE_AUTH` | `false` | Enable authentication requirement | No |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins (comma-separated) | Production |

**Example:**
```bash
API_KEY=sk_live_abc123def456...
REQUIRE_AUTH=true
ALLOWED_ORIGINS=https://myapp.com,https://api.myapp.com
```

### Redis Configuration

| Variable | Default | Description | Required |
|----------|---------|-------------|----------|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL | No |
| `REDIS_PASSWORD` | `""` | Redis authentication password | No |
| `REDIS_TIMEOUT` | `5` | Redis connection timeout (seconds) | No |
| `CACHE_TTL` | `3600` | Cache time-to-live (seconds) | No |

**Example:**
```bash
REDIS_URL=redis://username:password@redis-host:6379/0
REDIS_PASSWORD=your-redis-password
REDIS_TIMEOUT=10
CACHE_TTL=7200
```

### Rate Limiting

| Variable | Default | Description | Required |
|----------|---------|-------------|----------|
| `RATE_LIMIT_STORAGE` | `redis://localhost:6379/1` | Rate limiter storage URL | No |
| `DEFAULT_RATE_LIMIT` | `1000 per hour` | Default API rate limit | No |
| `BULK_RATE_LIMIT` | `10 per minute` | Bulk endpoint rate limit | No |
| `AUTH_RATE_LIMIT` | `5 per minute` | Authentication rate limit | No |

**Example:**
```bash
RATE_LIMIT_STORAGE=redis://localhost:6379/1
DEFAULT_RATE_LIMIT=5000 per hour
BULK_RATE_LIMIT=50 per minute
AUTH_RATE_LIMIT=10 per minute
```

### SMTP Settings

| Variable | Default | Description | Required |
|----------|---------|-------------|----------|
| `SMTP_TIMEOUT` | `10` | SMTP connection timeout (seconds) | No |
| `SMTP_RETRIES` | `3` | SMTP retry attempts | No |
| `SMTP_POOL_SIZE` | `10` | SMTP connection pool size | No |
| `SMTP_FROM_EMAIL` | `verify@localhost` | SMTP sender email | No |

**Example:**
```bash
SMTP_TIMEOUT=15
SMTP_RETRIES=2
SMTP_POOL_SIZE=20
SMTP_FROM_EMAIL=noreply@yourcompany.com
```

### Monitoring & Observability

| Variable | Default | Description | Required |
|----------|---------|-------------|----------|
| `SENTRY_DSN` | `""` | Sentry error tracking DSN | No |
| `PROMETHEUS_ENABLED` | `true` | Enable Prometheus metrics | No |
| `HEALTH_CHECK_INTERVAL` | `30` | Health check interval (seconds) | No |
| `METRICS_PORT` | `9090` | Prometheus metrics port | No |

**Example:**
```bash
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project
PROMETHEUS_ENABLED=true
HEALTH_CHECK_INTERVAL=60
METRICS_PORT=9090
```

## 🎯 Configuration Profiles

### Development Profile
```bash
# .env.development
ENV=development
DEBUG=true
REQUIRE_AUTH=false
LOG_LEVEL=DEBUG
REDIS_URL=redis://localhost:6379/0
CACHE_TTL=300
DEFAULT_RATE_LIMIT=10000 per hour
```

### Testing Profile
```bash
# .env.testing
ENV=testing
DEBUG=false
REQUIRE_AUTH=false
LOG_LEVEL=INFO
REDIS_URL=redis://localhost:6379/2
CACHE_TTL=60
SMTP_TIMEOUT=5
```

### Production Profile
```bash
# .env.production
ENV=production
DEBUG=false
REQUIRE_AUTH=true
LOG_LEVEL=WARNING
HOST=0.0.0.0
PORT=5004

# Security
API_KEY=sk_live_your_secure_api_key_here
ALLOWED_ORIGINS=https://yourdomain.com

# Redis
REDIS_URL=redis://username:password@redis.yourdomain.com:6379/0
REDIS_PASSWORD=your_secure_redis_password
CACHE_TTL=3600

# Rate Limiting
DEFAULT_RATE_LIMIT=1000 per hour
BULK_RATE_LIMIT=10 per minute

# Monitoring
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project
PROMETHEUS_ENABLED=true
```

## 🔒 Security Configuration

### Secure API Key Generation
```bash
# Generate secure API key
python -c "import secrets; print('sk_live_' + secrets.token_urlsafe(32))"
```

### CORS Configuration
```bash
# Single domain
ALLOWED_ORIGINS=https://myapp.com

# Multiple domains
ALLOWED_ORIGINS=https://myapp.com,https://api.myapp.com,https://admin.myapp.com

# Development (allow all - NOT for production)
ALLOWED_ORIGINS=*
```

### SSL/TLS Setup
```bash
# For HTTPS deployment
SSL_CERT_PATH=/path/to/certificate.crt
SSL_KEY_PATH=/path/to/private.key
FORCE_HTTPS=true
```

## ⚡ Performance Tuning

### High Performance Setup
```bash
# Redis optimization
REDIS_URL=redis://localhost:6379/0
REDIS_TIMEOUT=3
CACHE_TTL=7200

# SMTP optimization
SMTP_TIMEOUT=8
SMTP_POOL_SIZE=20
SMTP_RETRIES=2

# Rate limiting
DEFAULT_RATE_LIMIT=5000 per hour
BULK_RATE_LIMIT=50 per minute
```

### Memory Optimization
```bash
# Reduce memory usage
CACHE_TTL=1800
SMTP_POOL_SIZE=5
LOG_LEVEL=WARNING
```

### CPU Optimization
```bash
# Increase worker processes (Docker/Gunicorn)
WORKERS=4
WORKER_CONNECTIONS=1000
WORKER_TIMEOUT=30
```

## 📈 Monitoring Setup

### Basic Monitoring
```bash
# Enable all monitoring
PROMETHEUS_ENABLED=true
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project
LOG_LEVEL=INFO
HEALTH_CHECK_INTERVAL=30
```

### Advanced Monitoring
```bash
# Detailed metrics
PROMETHEUS_ENABLED=true
METRICS_PORT=9090
ENABLE_REQUEST_METRICS=true
ENABLE_BUSINESS_METRICS=true

# Error tracking
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project
SENTRY_ENVIRONMENT=production
SENTRY_TRACES_SAMPLE_RATE=0.1

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
ENABLE_ACCESS_LOGS=true
```

## 📊 Docker Configuration

### Docker Environment
```bash
# docker-compose.yml environment section
environment:
  - ENV=production
  - API_KEY=${API_KEY}
  - REDIS_URL=redis://redis:6379/0
  - REQUIRE_AUTH=true
```

### Kubernetes ConfigMap
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: email-api-config
data:
  ENV: "production"
  HOST: "0.0.0.0"
  PORT: "5004"
  REQUIRE_AUTH: "true"
  REDIS_URL: "redis://redis-service:6379/0"
  DEFAULT_RATE_LIMIT: "1000 per hour"
  LOG_LEVEL: "INFO"
```

## ✅ Production Checklist

### Security ✅
- [ ] Set strong `API_KEY` (32+ characters)
- [ ] Enable authentication (`REQUIRE_AUTH=true`)
- [ ] Configure CORS (`ALLOWED_ORIGINS`)
- [ ] Use HTTPS in production
- [ ] Set up error monitoring (Sentry)

### Performance ✅
- [ ] Configure Redis for caching
- [ ] Set appropriate rate limits
- [ ] Tune SMTP connection pool
- [ ] Configure log levels
- [ ] Set up monitoring

### Reliability ✅
- [ ] Configure health checks
- [ ] Set up proper logging
- [ ] Configure retry policies
- [ ] Set timeout values
- [ ] Plan backup strategies

### Monitoring ✅
- [ ] Enable Prometheus metrics
- [ ] Set up Grafana dashboards
- [ ] Configure alerting rules
- [ ] Set up log aggregation
- [ ] Monitor resource usage

## 🔧 Configuration Validation

### Validate Configuration
```bash
# Check configuration
python -c "
from config import Config
print('✅ Configuration loaded successfully')
print(f'Environment: {Config.api.ENV}')
print(f'Debug: {Config.api.DEBUG}')
print(f'Auth Required: {Config.security.REQUIRE_AUTH}')
print(f'Redis URL: {Config.database.REDIS_URL}')
"
```

### Test Configuration
```bash
# Run quick test
python quick_test.py

# Full test suite
python test_api.py
```

## 🆘 Troubleshooting

### Configuration Issues

**Missing Environment Variables:**
```bash
# Set required variables
export API_KEY=your-api-key
export REQUIRE_AUTH=true
```

**Redis Connection:**
```bash
# Test Redis connection
redis-cli -u redis://localhost:6379 ping
```

**Port Conflicts:**
```bash
# Use different port
export PORT=8080
```

**Permission Issues:**
```bash
# Check file permissions
chmod +x app.py
chmod 600 .env
```

---

## 💡 Pro Tips

1. **Start Simple**: Begin with default configuration, add complexity as needed
2. **Use Redis**: 4x performance improvement with Redis caching
3. **Monitor Everything**: Enable all monitoring in production
4. **Secure by Default**: Always use authentication in production
5. **Test Configuration**: Use `quick_test.py` to validate setup
6. **Environment Specific**: Use different `.env` files per environment
7. **Secrets Management**: Use proper secrets management in production
8. **Regular Updates**: Keep dependencies and configuration updated

For more details, see the [Complete API Documentation](./API_DOCUMENTATION.md). 