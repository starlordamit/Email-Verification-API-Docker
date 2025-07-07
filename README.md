# Production Email Verification API v2.0

[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-brightgreen.svg)](https://python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![API Version](https://img.shields.io/badge/API%20Version-2.0-orange.svg)](https://api.yourdomain.com/docs)

A high-performance, production-ready email verification service built with Flask, Redis caching, comprehensive monitoring, and enterprise-grade security features.

## 🚀 Features

### Core Verification
- **Advanced Email Validation**: RFC-compliant format validation with enhanced pattern detection
- **DNS & MX Record Verification**: Real-time DNS resolution and mail exchange validation
- **SMTP Mailbox Verification**: Direct SMTP testing with connection pooling
- **Domain Analysis**: Age verification, reputation scoring, and security assessment
- **Provider Detection**: Automatic identification of email service providers

### Performance & Scalability
- **Redis Caching**: Intelligent caching with configurable TTL
- **Connection Pooling**: Optimized SMTP connection management
- **Async Processing**: Non-blocking verification for bulk operations
- **Rate Limiting**: Multi-tier rate limiting with Redis backend
- **Bulk Processing**: Efficient batch verification up to 100 emails

### Security & Authentication
- **JWT Token Authentication**: Secure API access with role-based permissions
- **API Key Management**: Multiple authentication methods
- **Input Validation**: Comprehensive request sanitization
- **Security Headers**: Production-ready security middleware
- **Role-Based Access**: Admin, premium, and user role hierarchies

### Monitoring & Observability
- **Prometheus Metrics**: Complete application and system metrics
- **Health Checks**: Multi-level health monitoring
- **Structured Logging**: JSON-formatted logs with correlation IDs
- **Error Tracking**: Sentry integration for error monitoring
- **Performance Profiling**: Request timing and performance analysis

### Enterprise Features
- **Docker Ready**: Multi-stage builds with security best practices
- **High Availability**: Load balancer support with health checks
- **Configuration Management**: Environment-based configuration
- **Graceful Shutdown**: Proper signal handling and resource cleanup

## 📋 Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.11+ (for local development)
- Redis (included in Docker setup)

### 1. Clone and Setup
```bash
git clone <repository-url>
cd Email-Verification-API-Docker

# Copy environment template
cp .env.example .env
# Edit .env with your configuration
```

### 2. Start with Docker Compose
```bash
# Start all services (API, Redis, Monitoring)
docker-compose up -d

# View logs
docker-compose logs -f email-api

# Check service status
docker-compose ps
```

### 3. Verify Installation
```bash
# Health check
curl http://localhost:8000/health

# API info
curl http://localhost:8000/

# Test verification (if auth disabled)
curl "http://localhost:8000/api/v2/verify?email=test@gmail.com"
```

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENV` | `development` | Environment: development/production |
| `DEBUG` | `false` | Enable debug mode |
| `HOST` | `0.0.0.0` | Server host |
| `PORT` | `8000` | Server port |
| `WORKERS` | `4` | Gunicorn worker processes |

#### Authentication
| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | `` | Primary API key |
| `JWT_SECRET_KEY` | `` | JWT signing secret |
| `REQUIRE_AUTH` | `true` | Enable authentication |
| `JWT_EXPIRATION_HOURS` | `24` | JWT token lifetime |

#### Redis Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `REDIS_PASSWORD` | `` | Redis password |
| `CACHE_TTL` | `3600` | Cache TTL in seconds |

#### Rate Limiting
| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_DEFAULT` | `1000 per hour` | Default rate limit |
| `RATE_LIMIT_VERIFY` | `100 per minute` | Verification endpoint limit |
| `RATE_LIMIT_BULK` | `10 per minute` | Bulk verification limit |

#### SMTP Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_TIMEOUT` | `10` | SMTP connection timeout |
| `SMTP_FROM_EMAIL` | `verify@emailvalidator.com` | SMTP sender email |
| `SMTP_POOL_SIZE` | `10` | Connection pool size |

#### Monitoring
| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Logging level |
| `LOG_FORMAT` | `json` | Log format (json/text) |
| `METRICS_ENABLED` | `true` | Enable Prometheus metrics |
| `SENTRY_DSN` | `` | Sentry error tracking DSN |

## 📚 API Documentation

### Authentication

#### API Key Authentication
```bash
curl -H "X-API-Key: your-api-key" \
     http://localhost:8000/api/v2/verify?email=test@example.com
```

#### JWT Token Authentication
```bash
# Get token
curl -X POST http://localhost:8000/api/v2/auth/token \
     -H "Content-Type: application/json" \
     -d '{"user_id": "user123", "role": "user"}'

# Use token
curl -H "Authorization: Bearer your-jwt-token" \
     http://localhost:8000/api/v2/verify?email=test@example.com
```

### Endpoints

#### `GET/POST /api/v2/verify` - Single Email Verification

**Query Parameters (GET):**
- `email` (required): Email address to verify
- `skip_cache` (optional): Skip cache lookup

**Request Body (POST):**
```json
{
  "email": "user@example.com",
  "skip_cache": false
}
```

**Response:**
```json
{
  "success": true,
  "email": "user@example.com",
  "result": {
    "email_address": "user@example.com",
    "is_valid": true,
    "status": "deliverable",
    "confidence_score": 95,
    "validation_details": {
      "format": {
        "valid": true,
        "normalized": "user@example.com"
      },
      "dns": {
        "mx_found": true,
        "mx_records": ["mx1.example.com"]
      },
      "smtp": {
        "mailbox_exists": true,
        "response_code": 250
      }
    },
    "domain_details": {
      "domain": "example.com",
      "is_free_provider": false,
      "is_disposable": false
    },
    "provider_info": {
      "name": "Custom/Unknown",
      "type": "self-hosted",
      "reputation": "unknown"
    },
    "security_flags": {
      "is_role_account": false,
      "is_malicious_domain": false,
      "has_suspicious_pattern": false
    },
    "performance_metrics": {
      "total_time": 1.23
    },
    "timestamp": "2024-01-07T12:00:00Z"
  }
}
```

#### `POST /api/v2/bulk-verify` - Bulk Email Verification

**Request Body:**
```json
{
  "emails": [
    "user1@example.com",
    "user2@example.com",
    "user3@example.com"
  ],
  "skip_cache": false
}
```

**Response:**
```json
{
  "success": true,
  "total_processed": 3,
  "total_requested": 3,
  "unique_emails": 3,
  "processing_time_seconds": 2.45,
  "results": [
    {
      "email": "user1@example.com",
      "result": { /* verification result */ }
    },
    // ... more results
  ]
}
```

#### Status Values
- `deliverable`: Email exists and can receive mail
- `undeliverable`: Email does not exist or cannot receive mail
- `risky`: Email exists but has risk factors
- `invalid`: Email format is invalid
- `unknown`: Unable to determine status

### Interactive API Documentation

When running locally with `ENABLE_SWAGGER=true`, visit:
- **Swagger UI**: http://localhost:8000/api/docs/
- **OpenAPI Spec**: http://localhost:8000/api/spec.json

## 🚀 Deployment

### Production Docker Deployment

```bash
# Build production image
docker build --target production -t email-verification-api:latest .

# Run with production settings
docker run -d \
  --name email-api \
  -p 8000:8000 \
  -e ENV=production \
  -e API_KEY=your-secure-api-key \
  -e JWT_SECRET_KEY=your-secure-jwt-secret \
  -e REDIS_URL=redis://your-redis:6379/0 \
  email-verification-api:latest
```

### Docker Compose Production

```yaml
version: '3.8'
services:
  email-api:
    image: email-verification-api:latest
    environment:
      - ENV=production
      - API_KEY=${API_KEY}
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - redis
    restart: unless-stopped
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
        - containerPort: 8000
        env:
        - name: ENV
          value: "production"
        - name: REDIS_URL
          value: "redis://redis-service:6379/0"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
```

## 📊 Monitoring

### Health Checks

```bash
# Basic health check
curl http://localhost:8000/health

# Deep health check (requires admin role)
curl -H "X-API-Key: admin-key" \
     http://localhost:8000/health/deep
```

### Prometheus Metrics

Metrics available at `http://localhost:8000/metrics`:

- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request duration
- `email_verifications_total` - Total verifications by status
- `email_verification_duration_seconds` - Verification duration
- `system_cpu_usage_percent` - CPU usage
- `system_memory_usage_percent` - Memory usage
- `redis_active_connections` - Redis connections

### Grafana Dashboard

Access Grafana at `http://localhost:3000` (admin/admin) to view:
- API performance metrics
- System resource usage
- Email verification statistics
- Error rates and response times

### Log Analysis

Structured JSON logs include:
```json
{
  "timestamp": "2024-01-07T12:00:00Z",
  "level": "INFO",
  "logger": "app",
  "message": "Email verification completed",
  "email": "user@example.com",
  "status": "deliverable",
  "user_id": "user123",
  "request_id": "req-456"
}
```

## 🔒 Security

### Security Features
- Non-root container execution
- Input validation and sanitization
- Rate limiting with multiple tiers
- CORS protection
- Security headers (CSP, HSTS)
- JWT with expiration
- Structured audit logging

### Security Best Practices
1. **Use HTTPS in production**
2. **Set strong API keys and JWT secrets**
3. **Enable authentication** (`REQUIRE_AUTH=true`)
4. **Configure proper CORS origins**
5. **Monitor and alert on suspicious activity**
6. **Regularly update dependencies**
7. **Use secrets management for sensitive data**

### Rate Limiting

Default limits:
- **General API**: 1000 requests per hour
- **Email Verification**: 100 requests per minute  
- **Bulk Verification**: 10 requests per minute
- **Token Creation**: 5 requests per minute

## 🧪 Testing

### Run Tests
```bash
# Unit tests
docker-compose --profile testing run test-runner

# Manual testing
pytest tests/ -v --cov=.

# Load testing
ab -n 1000 -c 10 http://localhost:8000/health
```

### Test Coverage
```bash
# Generate coverage report
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

## 🛠️ Development

### Local Development Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-flask pytest-cov black flake8 mypy

# Start Redis
docker run -d -p 6379:6379 redis:alpine

# Run application
python app.py
```

### Code Quality
```bash
# Format code
black .

# Lint code
flake8 .

# Type checking
mypy .

# Run all checks
make check  # If Makefile exists
```

## 📈 Performance

### Benchmarks
- **Single verification**: ~200-500ms average
- **Bulk verification**: ~1-2 seconds for 10 emails
- **Cache hit**: <10ms response time
- **Throughput**: 1000+ requests/minute per worker

### Optimization Tips
1. **Enable Redis caching** for repeated verifications
2. **Use bulk endpoints** for multiple emails
3. **Scale workers** based on CPU cores
4. **Configure connection pooling** for high throughput
5. **Monitor and tune** based on metrics

## 🔧 Troubleshooting

### Common Issues

**503 Service Unavailable**
- Check Redis connectivity
- Verify SMTP pool health
- Review application logs

**429 Rate Limit Exceeded**
- Check rate limiting configuration
- Verify user authentication/role
- Consider upgrading limits

**Slow Response Times**
- Monitor SMTP connection timeouts
- Check DNS resolution performance
- Review cache hit rates

**Authentication Errors**
- Verify API key configuration
- Check JWT secret and expiration
- Review authentication logs

### Debug Mode
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG

# Disable authentication for testing
export REQUIRE_AUTH=false

# View detailed logs
docker-compose logs -f email-api
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📞 Support

- **Issues**: GitHub Issues
- **Documentation**: API Documentation at `/api/docs/`
- **Monitoring**: Grafana Dashboard at `:3000`

## 🗺️ Roadmap

- [ ] WebSocket support for real-time verification
- [ ] Machine learning-based risk scoring
- [ ] Advanced SMTP authentication
- [ ] Multi-region deployment support
- [ ] Enhanced security scanning
- [ ] API versioning and deprecation
- [ ] Advanced analytics dashboard
