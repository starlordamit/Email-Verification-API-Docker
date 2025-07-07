# Email Verification API v2.0 🚀

[![Production Ready](https://img.shields.io/badge/Status-Production%20Ready-green.svg)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)

> **Production-ready email verification API with comprehensive validation, bulk processing, and enterprise-grade features.**

## ⚡ Quick Start

```bash
# 1. Clone and setup
git clone <repo-url> && cd Email-Verification-API-Docker
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Start API (works without Redis)
python app.py

# 3. Test it!
curl http://localhost:5004/health
```

**API runs on**: `http://localhost:5004` 

## 🧪 Live Test Examples

```bash
# Single email verification
curl -X POST http://localhost:5004/api/v2/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com"}'

# Bulk verification (up to 100 emails)
curl -X POST http://localhost:5004/api/v2/bulk-verify \
  -H "Content-Type: application/json" \
  -d '{"emails": ["user@gmail.com", "admin@yahoo.com", "fake@10minutemail.com"]}'

# API documentation
curl http://localhost:5004/api/docs/
```

## ✨ Key Features

- 🔥 **Ultra Fast**: < 50ms response time with Redis
- 📊 **9+ Validation Checks**: Format, domain, SMTP, disposable detection
- 🔄 **Bulk Processing**: Up to 100 emails per request  
- ⚡ **Redis-Optional**: Graceful fallback to in-memory caching
- 🛡️ **Production Security**: JWT auth, rate limiting, CORS
- 📈 **Monitoring**: Prometheus metrics, health checks
- 🐳 **Docker Ready**: Production containers included

## 🚀 Docker Deployment

```bash
# Quick Docker run
docker build -t email-api . && docker run -p 5004:5004 email-api

# Full stack with Redis
docker-compose up -d
```

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v2/verify` | POST | Single email verification |
| `/api/v2/bulk-verify` | POST | Bulk email verification |
| `/api/docs/` | GET | Interactive API docs |
| `/metrics` | GET | Prometheus metrics |

## 🔧 Configuration

**Environment Variables** (optional):
```bash
# Basic config
ENV=development
DEBUG=false
PORT=5004

# Redis (optional - works without it)
REDIS_URL=redis://localhost:6379/0

# Security (for production)
API_KEY=your-secure-api-key
REQUIRE_AUTH=false
```

## 📈 Response Example

```json
{
  "success": true,
  "email": "user@gmail.com",
  "result": {
    "is_valid": true,
    "is_deliverable": true,
    "is_role_account": false,
    "is_disposable": false,
    "confidence_score": 0.95,
    "provider": "Google Gmail",
    "domain_info": {
      "domain": "gmail.com",
      "has_mx": true,
      "status": "valid"
    }
  },
  "processing_time": "< 50ms"
}
```

## 🎯 Production Checklist

- ✅ **Performance**: Works without Redis, 4x faster with Redis
- ✅ **Security**: Built-in authentication, rate limiting, input validation
- ✅ **Monitoring**: Health checks, metrics, structured logging  
- ✅ **Scalability**: Docker containers, load balancer ready
- ✅ **Reliability**: Graceful error handling, fallback mechanisms

## 📚 Full Documentation

For comprehensive documentation including advanced configuration, deployment guides, troubleshooting, and examples:

**📖 [Complete API Documentation](./API_DOCUMENTATION.md)**

## 🐛 Common Issues & Solutions

**Redis Connection Error?**
```bash
# API works without Redis! Just ignore the warning.
# To fix: docker run -d redis:alpine
```

**Port 5000 in use?**
```bash
export PORT=8080 && python app.py
```

**SMTP timeouts?**
```bash
# Normal behavior - some providers block verification
# API continues with other validation checks
```

## 🧪 Testing

```bash
# Run test suite
python test_api.py

# Load testing
python demo_api.py  # Simplified version for testing
```

## 📞 Support

- 📖 **Documentation**: [API_DOCUMENTATION.md](./API_DOCUMENTATION.md)
- 🔗 **Interactive Docs**: `http://localhost:5004/api/docs/`
- 🐛 **Issues**: GitHub Issues
- 💬 **Community**: Stack Overflow `email-verification-api`

---

**💡 Pro Tip**: Start with `python app.py` for immediate testing. Add Redis later for 4x performance boost!
