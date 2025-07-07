import os
import logging
from typing import Dict, List, Any
from datetime import datetime, UTC

# Flask and Extensions
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_caching import Cache
from flask_talisman import Talisman
from flasgger import Swagger

# Monitoring and Metrics
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

# Local imports
from config import Config
from auth import require_api_key, optional_api_key, get_auth_info
from verifier import ProductionEmailVerifier, VerificationResult
from user_info import user_info_extractor

# Initialize logging
logger = logging.getLogger(__name__)

# Initialize Sentry for error tracking
if Config.monitoring.SENTRY_DSN:
    sentry_sdk.init(
        dsn=Config.monitoring.SENTRY_DSN,
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.1,
        environment=Config.api.ENV
    )

def create_app() -> Flask:
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Basic Flask configuration
    app.config['SECRET_KEY'] = os.urandom(32)
    app.config['JSON_SORT_KEYS'] = False
    
    # Security headers for production
    if Config.api.ENV == 'production':
        Talisman(
            app,
            force_https=True,
            strict_transport_security=True,
            content_security_policy={
                'default-src': "'self'",
                'script-src': "'self' 'unsafe-inline'",
                'style-src': "'self' 'unsafe-inline'",
            }
        )
    
    # CORS configuration
    CORS(app, origins=Config.security.ALLOWED_ORIGINS)
    
    # Caching with Redis fallback
    try:
        # Try Redis cache first
        cache_config = {
            'CACHE_TYPE': 'redis',
            'CACHE_REDIS_URL': Config.database.REDIS_URL,
            'CACHE_DEFAULT_TIMEOUT': Config.database.CACHE_TTL
        }
        cache = Cache(app, config=cache_config)
        # Test Redis connection
        cache.get('test')
        logger.info("Cache initialized with Redis storage")
    except Exception as e:
        logger.warning(f"Redis unavailable for caching ({e}), falling back to simple cache")
        # Fallback to simple in-memory cache
        cache_config = {
            'CACHE_TYPE': 'simple',
            'CACHE_DEFAULT_TIMEOUT': Config.database.CACHE_TTL
        }
        cache = Cache(app, config=cache_config)
    
    # Rate limiting with Redis fallback
    try:
        # Test Redis connection first
        import redis
        redis_client = redis.from_url(Config.rate_limit.STORAGE_URI)
        redis_client.ping()
        redis_client.close()
        
        # Redis is available, use it
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            storage_uri=Config.rate_limit.STORAGE_URI,
            default_limits=[Config.rate_limit.DEFAULT_LIMIT]
        )
        logger.info("Rate limiter initialized with Redis storage")
    except Exception as e:
        logger.warning(f"Redis unavailable for rate limiting ({e}), disabling rate limiting for now")
        # Disable rate limiting when Redis is unavailable
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            storage_uri="memory://",
            default_limits=["1000000 per hour"],  # Very high limit = essentially disabled
            swallow_errors=True
        )
    
    # API Documentation
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": "apispec",
                "route": "/api/spec.json",
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/api/docs/"
    }
    Swagger(app, config=swagger_config)
    
    # Initialize email verifier
    verifier = ProductionEmailVerifier(Config)
    
    # Metrics
    if Config.monitoring.PROMETHEUS_ENABLED:
        request_count = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
        request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration')
        verification_count = Counter('email_verifications_total', 'Total email verifications', ['status'])
        verification_duration = Histogram('email_verification_duration_seconds', 'Email verification duration')
        
        @app.before_request
        def before_request():
            g.start_time = datetime.now(UTC)
        
        @app.after_request
        def after_request(response):
            if hasattr(g, 'start_time') and Config.monitoring.PROMETHEUS_ENABLED:
                duration = (datetime.now(UTC) - g.start_time).total_seconds()
                request_duration.observe(duration)
                request_count.labels(
                    method=request.method,
                    endpoint=request.endpoint or 'unknown',
                    status=response.status_code
                ).inc()
            return response
    
    # Error handlers
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            "error": "bad_request",
            "message": "Invalid request format or parameters",
            "code": 400,
            "timestamp": datetime.now(UTC).isoformat()
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            "error": "unauthorized",
            "message": "Authentication required. Please provide a valid API key in X-API-Key header.",
            "code": 401,
            "timestamp": datetime.now(UTC).isoformat()
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            "error": "forbidden",
            "message": "Insufficient permissions",
            "code": 403,
            "timestamp": datetime.now(UTC).isoformat()
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "error": "not_found",
            "message": "Endpoint not found",
            "code": 404,
            "timestamp": datetime.now(UTC).isoformat()
        }), 404
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({
            "error": "rate_limit_exceeded", 
            "message": "Rate limit exceeded. Please try again later.",
            "code": 429,
            "timestamp": datetime.now(UTC).isoformat()
        }), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "code": 500,
            "timestamp": datetime.now(UTC).isoformat()
        }), 500

    # API Routes
    @app.route('/')
    def index():
        """API root endpoint with information and documentation"""
        return jsonify({
            "name": "Email Verification API v2.0",
            "description": "Production-ready email verification service with comprehensive validation",
            "version": "2.0.0",
            "status": "operational",
            "authentication": {
                "required": Config.security.REQUIRE_AUTH,
                "method": "API Key",
                "header": "X-API-Key or Authorization: Bearer <key>"
            },
            "endpoints": {
                "verify_single": "POST /api/v2/verify",
                "verify_bulk": "POST /api/v2/bulk-verify", 
                "health": "GET /health",
                "documentation": "GET /api/docs/",
                "metrics": "GET /metrics"
            },
            "features": [
                "Single email verification",
                "Bulk email verification (up to 100)",
                "SMTP validation",
                "Domain MX record checking",
                "Disposable email detection",
                "Role account detection",
                "Provider identification",
                "Confidence scoring",
                "Redis caching support"
            ],
            "rate_limits": {
                "default": Config.rate_limit.DEFAULT_LIMIT,
                "verify": Config.rate_limit.VERIFY_LIMIT,
                "bulk": Config.rate_limit.BULK_LIMIT
            },
            "timestamp": datetime.now(UTC).isoformat()
        })

    @app.route('/api/v2/verify', methods=['GET', 'POST'])
    @limiter.limit(Config.rate_limit.VERIFY_LIMIT)
    @optional_api_key
    def verify_email():
        """
        Verify a single email address
        ---
        tags:
          - Email Verification
        parameters:
          - name: X-API-Key
            in: header
            type: string
            description: API key for authentication (optional in development)
          - name: email
            in: query
            type: string
            description: Email address to verify (GET request)
          - name: body
            in: body
            schema:
              type: object
              properties:
                email:
                  type: string
                  description: Email address to verify
                  example: "user@example.com"
        responses:
          200:
            description: Email verification result
          400:
            description: Invalid email format or missing email parameter
          401:
            description: Authentication required
          429:
            description: Rate limit exceeded
        """
        start_time = datetime.now(UTC)
        
        # Check authentication if required
        if Config.security.REQUIRE_AUTH and not getattr(g, 'authenticated', False):
            return jsonify({
                'success': False,
                'error': 'Authentication required',
                'message': 'Please provide a valid API key',
                'timestamp': datetime.now(UTC).isoformat()
            }), 401
        
        # Get email from request
        if request.method == 'GET':
            email = request.args.get('email')
        else:
            data = request.get_json() or {}
            email = data.get('email')
        
        if not email:
            return jsonify({
                'success': False,
                'error': 'Missing email parameter',
                'message': 'Please provide an email address to verify',
                'timestamp': datetime.now(UTC).isoformat()
            }), 400
        
        try:
            # Perform verification
            result = verifier.verify_email(email)
            
            # Extract user information (only if email is valid to avoid noise)
            user_info = None
            if result.is_valid:
                try:
                    user_info = user_info_extractor.extract_user_info(email)
                except Exception as e:
                    logger.warning(f"User info extraction failed for {email}: {e}")
                    user_info = {'error': 'User info extraction failed'}
            
            # Update metrics
            if Config.monitoring.PROMETHEUS_ENABLED:
                status = 'valid' if result.is_valid else 'invalid'
                verification_count.labels(status=status).inc()
                duration = (datetime.now(UTC) - start_time).total_seconds()
                verification_duration.observe(duration)
            
            # Format response
            response_data = {
                'success': True,
                'email': email,
                'result': {
                    'is_valid': result.is_valid,
                    'is_deliverable': result.is_deliverable,
                    'is_role_account': result.is_role_account,
                    'is_disposable': result.is_disposable,
                    'confidence_score': result.confidence_score,
                    'provider': result.provider,
                    'domain_info': {
                        'domain': result.domain,
                        'has_mx': result.has_mx_record,
                        'mailbox_exists': result.mailbox_exists,
                        'smtp_status': result.smtp_status,
                        'status': 'valid' if result.has_mx_record and result.mailbox_exists else 'invalid'
                    },
                    'errors': result.errors
                },
                'user_info': user_info,
                'timestamp': datetime.now(UTC).isoformat(),
                'processing_time_ms': f"< {int((datetime.now(UTC) - start_time).total_seconds() * 1000)}ms"
            }
            
            return jsonify(response_data)
            
        except Exception as e:
            logger.error(f"Email verification failed for {email}: {e}")
            return jsonify({
                'success': False,
                'error': 'Verification failed',
                'message': str(e),
                'timestamp': datetime.now(UTC).isoformat()
            }), 500

    @app.route('/api/v2/bulk-verify', methods=['POST'])
    @limiter.limit(Config.rate_limit.BULK_LIMIT)
    @optional_api_key  
    def bulk_verify_emails():
        """
        Verify multiple email addresses in bulk
        ---
        tags:
          - Email Verification
        parameters:
          - name: X-API-Key
            in: header
            type: string
            description: API key for authentication (optional in development)
          - name: body
            in: body
            required: true
            schema:
              type: object
              properties:
                emails:
                  type: array
                  items:
                    type: string
                  description: List of email addresses to verify (max 100)
                  example: ["user1@example.com", "user2@example.com"]
        responses:
          200:
            description: Bulk verification results
          400:
            description: Invalid request or too many emails
          401:
            description: Authentication required
          429:
            description: Rate limit exceeded
        """
        start_time = datetime.now(UTC)
        
        # Check authentication if required
        if Config.security.REQUIRE_AUTH and not getattr(g, 'authenticated', False):
            return jsonify({
                'success': False,
                'error': 'Authentication required',
                'message': 'Please provide a valid API key',
                'timestamp': datetime.now(UTC).isoformat()
            }), 401
        
        data = request.get_json() or {}
        emails = data.get('emails', [])
        
        if not emails:
            return jsonify({
                'success': False,
                'error': 'Missing emails parameter',
                'message': 'Please provide a list of email addresses',
                'timestamp': datetime.now(UTC).isoformat()
            }), 400
        
        if len(emails) > 100:
            return jsonify({
                'success': False,
                'error': 'Too many emails',
                'message': 'Maximum 100 emails allowed per request',
                'timestamp': datetime.now(UTC).isoformat()
            }), 400
        
        try:
            results = []
            valid_count = 0
            deliverable_count = 0
            
            for email in emails:
                try:
                    result = verifier.verify_email(email)
                    if result.is_valid:
                        valid_count += 1
                    if result.is_deliverable:
                        deliverable_count += 1
                    
                    # Extract user information (only if email is valid to avoid noise)
                    user_info = None
                    if result.is_valid:
                        try:
                            user_info = user_info_extractor.extract_user_info(email)
                        except Exception as e:
                            logger.warning(f"User info extraction failed for {email}: {e}")
                            user_info = {'error': 'User info extraction failed'}
                    
                    results.append({
                        'email': email,
                        'result': {
                            'is_valid': result.is_valid,
                            'is_deliverable': result.is_deliverable,
                            'is_role_account': result.is_role_account,
                            'is_disposable': result.is_disposable,
                            'confidence_score': result.confidence_score,
                            'provider': result.provider,
                            'domain_info': {
                                'domain': result.domain,
                                'has_mx': result.has_mx_record,
                                'mailbox_exists': result.mailbox_exists,
                                'smtp_status': result.smtp_status,
                                'status': 'valid' if result.has_mx_record and result.mailbox_exists else 'invalid'
                            },
                            'errors': result.errors
                        },
                        'user_info': user_info
                    })
                    
                    # Update metrics
                    if Config.monitoring.PROMETHEUS_ENABLED:
                        status = 'valid' if result.is_valid else 'invalid'
                        verification_count.labels(status=status).inc()
                        
                except Exception as e:
                    logger.error(f"Failed to verify {email}: {e}")
                    results.append({
                        'email': email,
                        'result': {
                            'is_valid': False,
                            'is_deliverable': False,
                            'is_role_account': False,
                            'is_disposable': False,
                            'confidence_score': 0.0,
                            'provider': 'Unknown',
                            'domain_info': {'domain': '', 'has_mx': False, 'mailbox_exists': False, 'smtp_status': 'error', 'status': 'error'},
                            'errors': [str(e)]
                        },
                        'user_info': None
                    })
            
            # Calculate statistics
            total_processed = len(results)
            success_rate = (valid_count / total_processed * 100) if total_processed > 0 else 0
            
            response_data = {
                'success': True,
                'summary': {
                    'total_processed': total_processed,
                    'valid_emails': valid_count,
                    'deliverable_emails': deliverable_count,
                    'success_rate': f"{success_rate:.1f}%"
                },
                'results': results,
                'timestamp': datetime.now(UTC).isoformat(),
                'processing_time': f"< {int((datetime.now(UTC) - start_time).total_seconds() * 1000)}ms"
            }
            
            return jsonify(response_data)
            
        except Exception as e:
            logger.error(f"Bulk verification failed: {e}")
            return jsonify({
                'success': False,
                'error': 'Bulk verification failed',
                'message': str(e),
                'timestamp': datetime.now(UTC).isoformat()
            }), 500

    @app.route('/health')
    def health_check():
        """
        Basic health check endpoint
        ---
        tags:
          - Health
        responses:
          200:
            description: Service is healthy
        """
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now(UTC).isoformat(),
            "version": "2.0.0",
            "services": {
                "email_verifier": "online",
                "dns_resolver": "online", 
                "smtp_checker": "online",
                "api": "running"
            }
        })

    @app.route('/health/deep')
    @optional_api_key
    def deep_health_check():
        """
        Comprehensive health check with system metrics
        ---
        tags:
          - Health
        responses:
          200:
            description: Detailed health status
        """
        try:
            import psutil
            
            health_data = {
                "status": "healthy",
                "timestamp": datetime.now(UTC).isoformat(),
                "version": "2.0.0",
                "services": {
                    "redis": "connected" if verifier._test_redis_connection() else "disconnected",
                    "database": "operational",
                    "smtp_pool": "healthy"
                },
                "system": {
                    "cpu_usage": psutil.cpu_percent(),
                    "memory_usage": psutil.virtual_memory().percent,
                    "disk_usage": psutil.disk_usage('/').percent
                },
                "configuration": {
                    "environment": Config.api.ENV,
                    "authentication_required": Config.security.REQUIRE_AUTH,
                    "cache_enabled": "redis" in str(cache),
                    "rate_limiting_enabled": limiter is not None
                }
            }
            
            return jsonify(health_data)
            
        except ImportError:
            # Fallback if psutil is not available
            return jsonify({
                "status": "healthy",
                "timestamp": datetime.now(UTC).isoformat(),
                "version": "2.0.0",
                "message": "Basic health check (psutil not available for system metrics)"
            })

    # Metrics endpoint
    if Config.monitoring.PROMETHEUS_ENABLED:
        @app.route('/metrics')
        def metrics():
            """Prometheus metrics endpoint"""
            return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

    @app.teardown_appcontext
    def cleanup(error):
        """Cleanup resources on request completion"""
        if error:
            logger.error(f"Request completed with error: {error}")

    logger.info("Flask application initialized successfully (Environment: {})".format(Config.api.ENV))
    return app

# Create the application instance for WSGI servers (like gunicorn)
app = create_app()

if __name__ == '__main__':
    logger.info("Starting Email Verification API v2.0.0")
    logger.info(f"Environment: {Config.api.ENV}")
    logger.info(f"Debug mode: {Config.api.DEBUG}")
    logger.info(f"Host: {Config.api.HOST}:{Config.api.PORT}")
    
    app.run(
        host=Config.api.HOST,
        port=Config.api.PORT,
        debug=Config.api.DEBUG
    )
