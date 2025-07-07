# Email Verification API v2.0 - Complete Documentation

[![Production Ready](https://img.shields.io/badge/Status-Production%20Ready-green.svg)](https://github.com)
[![API Version](https://img.shields.io/badge/API%20Version-2.0.0-blue.svg)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-orange.svg)](https://flask.palletsprojects.com)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [API Endpoints](#api-endpoints)
- [Configuration](#configuration)
- [Docker Deployment](#docker-deployment)
- [Testing](#testing)
- [Performance](#performance)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

## 🚀 Overview

The Email Verification API v2.0 is a production-ready service that provides comprehensive email address validation and verification. Built with Flask, it offers enterprise-grade features including SMTP validation, domain checking, disposable email detection, and bulk processing capabilities.

### Key Benefits

- **🔥 High Performance**: < 50ms response time for single emails
- **📊 Comprehensive Analysis**: 9+ validation checks per email
- **🔄 Bulk Processing**: Up to 100 emails per request
- **⚡ Redis-Optional**: Works with or without Redis caching
- **🛡️ Production Security**: JWT auth, rate limiting, CORS support
- **📈 Monitoring Ready**: Prometheus metrics, health checks
- **🐳 Docker Ready**: Multi-stage builds with security best practices

## ✨ Features

### Core Email Verification
- ✅ **Format Validation**: RFC-compliant email format checking
- ✅ **Domain Validation**: MX record lookup and DNS verification
- ✅ **SMTP Verification**: Real-time SMTP server connectivity testing
- ✅ **Disposable Email Detection**: Identifies temporary email services
- ✅ **Role Account Detection**: Finds admin, support, info emails
- ✅ **Provider Identification**: Recognizes Gmail, Yahoo, Outlook, etc.
- ✅ **Confidence Scoring**: 0.0-1.0 reliability scoring system
- ✅ **Suspicious Pattern Detection**: Identifies potentially fake emails

### Advanced Features
- 🔄 **Bulk Verification**: Process up to 100 emails simultaneously
- 📊 **Detailed Analytics**: Success rates, processing times, statistics
- 🚀 **High Performance**: Redis caching with connection pooling
- 🔒 **Enterprise Security**: JWT authentication, API keys, rate limiting
- 📈 **Monitoring**: Prometheus metrics, health checks, system stats
- 🐳 **Container Ready**: Docker and Kubernetes deployment support

### 👤 NEW: User Information Extraction
- **Name Detection**: Extract first/last names from email patterns
- **Profile Pictures**: Gravatar integration with avatar URLs
- **Professional Analysis**: Detect corporate vs personal emails
- **Social Profiles**: Suggest potential social media accounts
- **Domain Intelligence**: Classify email providers and types
- **Confidence Scoring**: Rate extraction accuracy (0.0-1.0)

## ⚡ Quick Start

### Prerequisites
- Python 3.8+
- Redis (optional - API works without it)
- Docker (optional)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd Email-Verification-API-Docker

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the API
python app.py
```

### Basic Usage

```bash
# Health check
curl http://localhost:5004/health

# Verify single email
curl -X POST http://localhost:5004/api/v2/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'

# Bulk verification
curl -X POST http://localhost:5004/api/v2/bulk-verify \
  -H "Content-Type: application/json" \
  -d '{"emails": ["user@gmail.com", "admin@yahoo.com"]}'
```

## 🔌 API Endpoints

### Base URL
- **Development**: `http://localhost:5004`
- **Production**: `https://your-domain.com`

### Authentication
Most endpoints support optional authentication:
- **API Key**: `X-API-Key: your-api-key`
- **JWT Token**: `Authorization: Bearer your-jwt-token`

---

### 📊 Health & Status

#### `GET /health`
Basic health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-07-07T14:51:39.204322",
  "version": "2.0.0",
  "services": {
    "email_verifier": "online",
    "dns_resolver": "online", 
    "smtp_checker": "online",
    "api": "running"
  }
}
```

#### `GET /health/deep`
Comprehensive health check with system metrics.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-07-07T14:51:39.204322",
  "version": "2.0.0",
  "services": {
    "redis": "connected",
    "database": "operational",
    "smtp_pool": "healthy"
  },
  "system": {
    "cpu_usage": 15.2,
    "memory_usage": 45.8,
    "disk_usage": 23.1
  }
}
```

#### `GET /stats`
API usage statistics and metrics.

---

### 📧 Email Verification

#### `POST /api/v2/verify`
Verify a single email address.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "email": "john.doe@gmail.com",
  "result": {
    "is_valid": true,
    "is_deliverable": true,
    "is_role_account": false,
    "is_disposable": false,
    "confidence_score": 0.85,
    "provider": "Gmail",
    "domain_info": {
      "domain": "gmail.com",
      "has_mx": true,
      "status": "valid"
    },
    "errors": []
  },
  "user_info": {
    "email": "john.doe@gmail.com",
    "extracted_info": {
      "names": {
        "first_name": "John",
        "last_name": "Doe",
        "full_name": "John Doe",
        "username": "john.doe",
        "extraction_method": "pattern_0_two_parts"
      },
      "profile_picture": {
        "gravatar_hash": "abc123...",
        "avatar_url": "https://www.gravatar.com/avatar/abc123...?s=200",
        "has_gravatar": true,
        "profile_data": {
          "display_name": "John Doe",
          "real_name": "John Doe",
          "location": "San Francisco, CA",
          "social_accounts": [
            {
              "platform": "GitHub",
              "url": "https://github.com/johndoe",
              "title": "GitHub Profile"
            }
          ]
        }
      },
      "social_profiles": {
        "potential_profiles": [
          {
            "platform": "GitHub",
            "url": "https://github.com/john.doe",
            "confidence": "low",
            "note": "Potential profile - not verified"
          }
        ],
        "domain_type": {
          "platform": "Google",
          "type": "email"
        }
      },
      "professional_info": {
        "is_professional": false,
        "email_type": "personal",
        "company_domain": "gmail.com"
      },
      "domain_info": {
        "domain": "gmail.com",
        "type": "email",
        "platform": "Google"
      }
    },
    "confidence_score": 0.75
  },
  "timestamp": "2025-07-07T14:51:39.407418",
  "processing_time_ms": "< 50ms"
}
```

**Field Descriptions:**
- `is_valid`: Email format is valid
- `is_deliverable`: Email can receive messages (SMTP check passed)
- `is_role_account`: Email is admin/support/info type
- `is_disposable`: Email is from temporary service
- `confidence_score`: Overall reliability (0.0-1.0)
- `provider`: Email service provider name
- `domain_info`: Domain validation details

**👤 User Information Fields:**
- `user_info.extracted_info.names`: Extracted first/last names and extraction method
- `user_info.extracted_info.profile_picture`: Gravatar avatar and profile data
- `user_info.extracted_info.social_profiles`: Potential social media accounts
- `user_info.extracted_info.professional_info`: Corporate vs personal email analysis
- `user_info.extracted_info.domain_info`: Email provider classification
- `user_info.confidence_score`: User info extraction reliability (0.0-1.0)

**Note**: User information extraction only runs for valid emails to reduce processing overhead.

#### `POST /api/v2/bulk-verify`
Verify multiple emails in a single request.

**Request:**
```json
{
  "emails": [
    "user@gmail.com",
    "admin@yahoo.com", 
    "fake@nonexistent.com"
  ]
}
```

**Response:**
```json
{
  "success": true,
  "summary": {
    "total_processed": 3,
    "valid_emails": 2,
    "deliverable_emails": 1,
    "success_rate": "66.7%"
  },
  "results": [
    {
      "email": "user@gmail.com",
      "result": {
        "is_valid": true,
        "is_deliverable": true,
        "is_role_account": false,
        "is_disposable": false,
        "confidence_score": 0.95,
        "provider": "Google Gmail"
      }
    }
  ],
  "timestamp": "2025-07-07T14:52:20.113818",
  "processing_time": "< 150ms"
}
```

**Limits:**
- Maximum 100 emails per request
- Rate limit: 1000 requests per hour (configurable)

---

### 🔒 Authentication

Authentication is **optional by default** and uses simple API keys stored in environment variables.

**Configuration:**
```bash
# Enable authentication (optional)
REQUIRE_AUTH=true
API_KEY=your-secure-api-key-here
```

**Usage:**
```bash
# Option 1: X-API-Key header
curl -H "X-API-Key: your-api-key" http://localhost:5004/api/v2/verify

# Option 2: Authorization Bearer header  
curl -H "Authorization: Bearer your-api-key" http://localhost:5004/api/v2/verify
```

---

### 📈 Monitoring

#### `GET /metrics`
Prometheus-compatible metrics endpoint.

#### `GET /api/docs/`
Interactive Swagger API documentation.

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Application
ENV=production
DEBUG=false
PORT=5004
HOST=0.0.0.0

# Security
API_KEY=your-secure-api-key-here
REQUIRE_AUTH=false

# Redis (Optional)
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=your-redis-password
REDIS_TIMEOUT=5
CACHE_TTL=3600

# Rate Limiting
RATE_LIMIT_STORAGE=redis://localhost:6379/1
DEFAULT_RATE_LIMIT=1000 per hour
BURST_RATE_LIMIT=100 per minute

# SMTP Settings
SMTP_TIMEOUT=10
SMTP_RETRIES=3
SMTP_POOL_SIZE=10

# Monitoring
SENTRY_DSN=https://your-sentry-dsn
PROMETHEUS_ENABLED=true
LOG_LEVEL=INFO

# CORS
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
```

### Configuration Classes

The API uses environment-based configuration with fallbacks:

```python
# Development
ENV=development
DEBUG=true
REQUIRE_AUTH=false

# Production  
ENV=production
DEBUG=false
REQUIRE_AUTH=true
```

## 🐳 Docker Deployment

### Quick Docker Run

```bash
# Build the image
docker build -t email-verification-api .

# Run with environment variables
docker run -d \
  --name email-api \
  -p 5004:5004 \
  -e ENV=production \
  -e API_KEY=your-secure-key \
  email-verification-api
```

### Docker Compose (Recommended)

```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "5004:5004"
    environment:
      - ENV=production
      - REDIS_URL=redis://redis:6379/0
      - API_KEY=your-secure-api-key
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - api
    restart: unless-stopped

volumes:
  redis_data:
```

Start the complete stack:
```bash
docker-compose up -d
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: email-verification-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: email-verification-api
  template:
    metadata:
      labels:
        app: email-verification-api
    spec:
      containers:
      - name: api
        image: email-verification-api:latest
        ports:
        - containerPort: 5004
        env:
        - name: ENV
          value: "production"
        - name: REDIS_URL
          value: "redis://redis-service:6379/0"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

## 🧪 Testing

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov requests

# Run comprehensive test suite
python test_api.py

# Run with coverage
pytest --cov=. --cov-report=html

# Load testing (requires k6)
k6 run load_test.js
```

### Test Scenarios

```bash
# 1. Health check
curl http://localhost:5004/health

# 2. Valid email
curl -X POST http://localhost:5004/api/v2/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com"}'

# 3. Invalid email
curl -X POST http://localhost:5004/api/v2/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "invalid-email"}'

# 4. Role account
curl -X POST http://localhost:5004/api/v2/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@company.com"}'

# 5. Disposable email
curl -X POST http://localhost:5004/api/v2/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "test@10minutemail.com"}'

# 6. Bulk verification
curl -X POST http://localhost:5004/api/v2/bulk-verify \
  -H "Content-Type: application/json" \
  -d '{"emails": ["user@gmail.com", "admin@yahoo.com", "fake@fake.com"]}'
```

## 📊 Performance

### Benchmarks

| Metric | Without Redis | With Redis | 
|--------|---------------|------------|
| Single Email | ~200ms | ~50ms |
| Bulk (10 emails) | ~2s | ~500ms |
| Bulk (100 emails) | ~20s | ~5s |
| Throughput | 300 req/min | 1200 req/min |
| Memory Usage | 150MB | 200MB |

### Optimization Tips

1. **Enable Redis**: 4x performance improvement
2. **Use Bulk Endpoints**: Process multiple emails efficiently
3. **Configure Connection Pooling**: Reduce SMTP connection overhead
4. **Enable Caching**: Cache domain and MX record lookups
5. **Load Balancing**: Use multiple API instances

### Rate Limits

- **Default**: 1000 requests per hour per IP
- **Burst**: 100 requests per minute per IP
- **Bulk**: 10 bulk requests per minute per IP
- **API Key**: Higher limits for authenticated requests

## 🔒 Security

### Authentication Methods

1. **API Key Authentication**
   ```bash
   curl -H "X-API-Key: your-api-key" http://localhost:5004/api/v2/verify
   ```

2. **JWT Token Authentication**
   ```bash
   curl -H "Authorization: Bearer your-jwt-token" http://localhost:5004/api/v2/verify
   ```

### Security Features

- ✅ **Input Validation**: All inputs sanitized and validated
- ✅ **Rate Limiting**: Prevents abuse and DDoS attacks
- ✅ **CORS Protection**: Configurable cross-origin policies
- ✅ **Security Headers**: XSS, CSRF, clickjacking protection
- ✅ **SSL/TLS**: HTTPS encryption in production
- ✅ **API Key Rotation**: Support for key management
- ✅ **Audit Logging**: Request logging and monitoring

### Best Practices

1. **Use HTTPS**: Always encrypt API communications
2. **Rotate API Keys**: Regular key rotation schedule
3. **Monitor Usage**: Track API usage patterns
4. **Rate Limiting**: Implement appropriate limits
5. **Input Validation**: Validate all inputs server-side
6. **Error Handling**: Don't expose internal errors

## 🔧 Troubleshooting

### Common Issues

#### 1. Redis Connection Failed
```
ERROR: Redis unavailable for caching (Connection refused)
```

**Solution:**
- The API works without Redis with fallback to in-memory caching
- Start Redis: `redis-server` or `docker run -d redis:alpine`
- Check Redis URL in environment variables

#### 2. SMTP Verification Timeouts
```
WARNING: SMTP verification failed for domain example.com
```

**Solution:**
- Increase SMTP timeout: `SMTP_TIMEOUT=30`
- Some email providers block verification attempts
- This is normal - the API continues with other checks

#### 3. High Memory Usage
```
INFO: Memory usage: 85%
```

**Solution:**
- Enable Redis to reduce memory caching
- Reduce cache TTL: `CACHE_TTL=1800`
- Scale horizontally with load balancer

#### 4. Rate Limit Exceeded
```
HTTP 429: Rate limit exceeded
```

**Solution:**
- Increase rate limits in configuration
- Use authentication for higher limits
- Implement retry logic with exponential backoff

### Debug Mode

Enable debug logging:
```bash
export DEBUG=true
export LOG_LEVEL=DEBUG
python app.py
```

### Health Monitoring

Monitor API health:
```bash
# Basic health
curl http://localhost:5004/health

# Detailed health with metrics
curl http://localhost:5004/health/deep

# Prometheus metrics
curl http://localhost:5004/metrics
```

## 📚 Additional Resources

### API Client Libraries

- **Python**: Use `requests` library (examples in this doc)
- **JavaScript**: Use `fetch` or `axios`
- **PHP**: Use `cURL` or `Guzzle`
- **Java**: Use `OkHttp` or `Apache HttpClient`

### Integration Examples

Check the `/examples` directory for:
- Web form integration
- Bulk processing scripts
- Real-time validation
- Webhook implementations

### Support

- **Documentation**: This file
- **API Reference**: `/api/docs/` endpoint
- **Issues**: GitHub Issues
- **Community**: Stack Overflow with `email-verification-api` tag

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

**Built with ❤️ for production email verification needs** 