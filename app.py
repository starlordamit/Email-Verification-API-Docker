import os
import sys
import logging
import asyncio
from typing import Dict, List, Any
from datetime import datetime, timedelta

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
from auth import require_auth, require_role, log_request, AuthTokenManager
from verifier import ProductionEmailVerifier, VerificationResult

# Initialize logging first
Config.setup_logging()
logger = logging.getLogger(__name__)

# Validate configuration
if not Config.validate():
    logger.error("Configuration validation failed. Exiting.")
    sys.exit(1)

# Initialize Sentry for error tracking
if Config.monitoring.SENTRY_DSN:
    sentry_sdk.init(
        dsn=Config.monitoring.SENTRY_DSN,
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.1,
        environment=Config.ENV
    )

def create_app() -> Flask:
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Basic Flask configuration
    app.config['SECRET_KEY'] = Config.security.JWT_SECRET_KEY or os.urandom(32)
    app.config['MAX_CONTENT_LENGTH'] = Config.security.MAX_CONTENT_LENGTH
    app.config['JSON_SORT_KEYS'] = False
    
    # Security headers
    if Config.is_production():
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
    
    # Caching
    cache_config = {
        'CACHE_TYPE': 'redis',
        'CACHE_REDIS_URL': Config.database.REDIS_URL,
        'CACHE_DEFAULT_TIMEOUT': Config.database.CACHE_TTL
    }
    cache = Cache(app, config=cache_config)
    
    # Rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        storage_uri=Config.rate_limit.STORAGE_URI,
        default_limits=[Config.rate_limit.DEFAULT_LIMIT]
    )
    
    # API Documentation
    if Config.api.ENABLE_SWAGGER:
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
    if Config.monitoring.METRICS_ENABLED:
        request_count = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
        request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration')
        verification_count = Counter('email_verifications_total', 'Total email verifications', ['status'])
        verification_duration = Histogram('email_verification_duration_seconds', 'Email verification duration')
        
        @app.before_request
        def before_request():
            g.start_time = datetime.utcnow()
        
        @app.after_request
        def after_request(response):
            if hasattr(g, 'start_time') and Config.monitoring.METRICS_ENABLED:
                duration = (datetime.utcnow() - g.start_time).total_seconds()
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
            "timestamp": datetime.utcnow().isoformat()
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            "error": "unauthorized",
            "message": "Authentication required",
            "code": 401,
            "timestamp": datetime.utcnow().isoformat()
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            "error": "forbidden",
            "message": "Insufficient permissions",
            "code": 403,
            "timestamp": datetime.utcnow().isoformat()
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "error": "not_found",
            "message": "Endpoint not found",
            "code": 404,
            "timestamp": datetime.utcnow().isoformat()
        }), 404
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({
            "error": "rate_limit_exceeded",
            "message": str(error.description),
            "code": 429,
            "timestamp": datetime.utcnow().isoformat(),
            "retry_after": error.retry_after if hasattr(error, 'retry_after') else None
        }), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}", exc_info=True)
        return jsonify({
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "code": 500,
            "timestamp": datetime.utcnow().isoformat()
        }), 500
    
    # Routes
    @app.route('/')
    def index():
        """
        API Information Endpoint
        ---
        tags:
          - General
        responses:
          200:
            description: API information
            schema:
              type: object
              properties:
                service:
                  type: string
                version:
                  type: string
                status:
                  type: string
                documentation:
                  type: string
        """
        return jsonify({
            "service": Config.api.TITLE,
            "version": Config.api.VERSION,
            "description": Config.api.DESCRIPTION,
            "status": "operational",
            "environment": Config.ENV,
            "documentation": "/api/docs/" if Config.api.ENABLE_SWAGGER else None,
            "endpoints": {
                "verify": "/api/v2/verify",
                "bulk_verify": "/api/v2/bulk-verify",
                "health": "/health",
                "metrics": "/metrics" if Config.monitoring.METRICS_ENABLED else None
            },
            "timestamp": datetime.utcnow().isoformat()
        })
    
    @app.route('/api/v2/verify', methods=['GET', 'POST'])
    @limiter.limit(Config.rate_limit.VERIFY_LIMIT)
    @require_auth
    @log_request
    def verify_email():
        """
        Single Email Verification
        ---
        tags:
          - Verification
        parameters:
          - name: email
            in: query
            type: string
            required: true
            description: Email address to verify
          - name: skip_cache
            in: query
            type: boolean
            default: false
            description: Skip cache lookup
        security:
          - ApiKeyAuth: []
        responses:
          200:
            description: Verification result
            schema:
              type: object
              properties:
                success:
                  type: boolean
                email:
                  type: string
                result:
                  type: object
          400:
            description: Invalid email parameter
          401:
            description: Authentication required
          429:
            description: Rate limit exceeded
        """
        try:
            # Get email from query params or JSON body
            email = None
            skip_cache = False
            
            if request.method == 'GET':
                email = request.args.get('email', '').strip()
                skip_cache = request.args.get('skip_cache', 'false').lower() == 'true'
            else:  # POST
                data = request.get_json() or {}
                email = data.get('email', '').strip()
                skip_cache = data.get('skip_cache', False)
            
            if not email:
                return jsonify({
                    "success": False,
                    "error": "validation_error",
                    "message": "Email parameter is required",
                    "code": 400
                }), 400
            
            # Perform verification
            start_time = datetime.utcnow()
            result = verifier.verify_email(email, skip_cache=skip_cache)
            
            # Update metrics
            if Config.monitoring.METRICS_ENABLED:
                verification_duration.observe((datetime.utcnow() - start_time).total_seconds())
                verification_count.labels(status=result.status).inc()
            
            response_data = {
                "success": True,
                "email": email,
                "result": result.to_dict(),
                "cached": not skip_cache and hasattr(result, '_from_cache'),
                "user_id": g.current_user.get('user_id'),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(f"Email verification completed: {email} -> {result.status}")
            return jsonify(response_data)
        
        except Exception as e:
            logger.error(f"Verification error for {email}: {e}", exc_info=True)
            return jsonify({
                "success": False,
                "error": "verification_error",
                "message": "Failed to verify email address",
                "code": 500
            }), 500
    
    @app.route('/api/v2/bulk-verify', methods=['POST'])
    @limiter.limit(Config.rate_limit.BULK_LIMIT)
    @require_auth
    @log_request
    def bulk_verify_emails():
        """
        Bulk Email Verification
        ---
        tags:
          - Verification
        parameters:
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
                  maxItems: 100
                skip_cache:
                  type: boolean
                  default: false
        security:
          - ApiKeyAuth: []
        responses:
          200:
            description: Bulk verification results
          400:
            description: Invalid request format
          401:
            description: Authentication required
          429:
            description: Rate limit exceeded
        """
        try:
            data = request.get_json()
            if not data or 'emails' not in data:
                return jsonify({
                    "success": False,
                    "error": "validation_error",
                    "message": "emails array is required",
                    "code": 400
                }), 400
            
            emails = data['emails']
            skip_cache = data.get('skip_cache', False)
            
            # Validate input
            if not isinstance(emails, list):
                return jsonify({
                    "success": False,
                    "error": "validation_error",
                    "message": "emails must be an array",
                    "code": 400
                }), 400
            
            if len(emails) > Config.api.MAX_BULK_SIZE:
                return jsonify({
                    "success": False,
                    "error": "validation_error",
                    "message": f"Maximum {Config.api.MAX_BULK_SIZE} emails allowed per request",
                    "code": 400
                }), 400
            
            # Clean and deduplicate emails
            unique_emails = list(set(email.strip().lower() for email in emails if email.strip()))
            
            if not unique_emails:
                return jsonify({
                    "success": False,
                    "error": "validation_error",
                    "message": "No valid emails provided",
                    "code": 400
                }), 400
            
            # Process bulk verification
            start_time = datetime.utcnow()
            results = []
            
            # For production, implement async processing
            for email in unique_emails:
                try:
                    result = verifier.verify_email(email, skip_cache=skip_cache)
                    results.append({
                        "email": email,
                        "result": result.to_dict()
                    })
                    
                    if Config.monitoring.METRICS_ENABLED:
                        verification_count.labels(status=result.status).inc()
                        
                except Exception as e:
                    logger.error(f"Bulk verification error for {email}: {e}")
                    results.append({
                        "email": email,
                        "result": {
                            "status": "error",
                            "error": str(e)
                        }
                    })
            
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            response_data = {
                "success": True,
                "total_processed": len(results),
                "total_requested": len(emails),
                "unique_emails": len(unique_emails),
                "results": results,
                "processing_time_seconds": processing_time,
                "user_id": g.current_user.get('user_id'),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(f"Bulk verification completed: {len(unique_emails)} emails processed")
            return jsonify(response_data)
        
        except Exception as e:
            logger.error(f"Bulk verification error: {e}", exc_info=True)
            return jsonify({
                "success": False,
                "error": "bulk_verification_error",
                "message": "Failed to process bulk verification",
                "code": 500
            }), 500
    
    @app.route('/api/v2/auth/token', methods=['POST'])
    @limiter.limit("5 per minute")
    def create_auth_token():
        """
        Create Authentication Token
        ---
        tags:
          - Authentication
        parameters:
          - name: body
            in: body
            required: true
            schema:
              type: object
              properties:
                user_id:
                  type: string
                role:
                  type: string
                  enum: [user, premium, admin]
        responses:
          200:
            description: Token created successfully
          400:
            description: Invalid request
        """
        try:
            data = request.get_json()
            user_id = data.get('user_id')
            role = data.get('role', 'user')
            
            if not user_id:
                return jsonify({
                    "error": "validation_error",
                    "message": "user_id is required"
                }), 400
            
            token = AuthTokenManager.create_api_token(user_id, role)
            
            return jsonify({
                "success": True,
                "token": token,
                "user_id": user_id,
                "role": role,
                "expires_in": Config.security.JWT_EXPIRATION_HOURS * 3600
            })
        
        except Exception as e:
            logger.error(f"Token creation error: {e}")
            return jsonify({
                "error": "token_creation_error",
                "message": "Failed to create token"
            }), 500
    
    @app.route('/health')
    def health_check():
        """
        Health Check Endpoint
        ---
        tags:
          - Monitoring
        responses:
          200:
            description: Service is healthy
          503:
            description: Service is unhealthy
        """
        health_status = {
            "service": "email-verification-api",
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": Config.api.VERSION,
            "environment": Config.ENV,
            "checks": {}
        }
        
        # Redis connectivity check
        try:
            if verifier.cache.redis_client:
                verifier.cache.redis_client.ping()
                health_status["checks"]["redis"] = "healthy"
            else:
                health_status["checks"]["redis"] = "disabled"
        except Exception as e:
            health_status["checks"]["redis"] = f"unhealthy: {str(e)}"
            health_status["status"] = "degraded"
        
        # SMTP pool check
        try:
            smtp_stats = verifier.get_metrics()
            health_status["checks"]["smtp_pool"] = "healthy"
            health_status["smtp_connections"] = smtp_stats["smtp_pool_stats"]["active_connections"]
        except Exception as e:
            health_status["checks"]["smtp_pool"] = f"unhealthy: {str(e)}"
            health_status["status"] = "degraded"
        
        status_code = 200 if health_status["status"] == "healthy" else 503
        return jsonify(health_status), status_code
    
    @app.route('/health/deep')
    @require_role('admin')
    def deep_health_check():
        """
        Deep Health Check (Admin Only)
        ---
        tags:
          - Monitoring
        security:
          - ApiKeyAuth: []
        responses:
          200:
            description: Detailed health information
        """
        try:
            # Test actual email verification
            test_result = verifier.verify_email("test@gmail.com", skip_cache=True)
            
            health_data = {
                "service": "email-verification-api",
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "detailed_checks": {
                    "email_verification": {
                        "status": "healthy" if test_result.status != "error" else "unhealthy",
                        "test_email": "test@gmail.com",
                        "test_result": test_result.status,
                        "response_time": test_result.performance_metrics.get('total_time', 0)
                    },
                    "cache": {
                        "enabled": verifier.cache.redis_client is not None,
                        "status": "healthy" if verifier.cache.redis_client else "disabled"
                    },
                    "metrics": verifier.get_metrics()
                }
            }
            
            return jsonify(health_data)
        
        except Exception as e:
            logger.error(f"Deep health check error: {e}")
            return jsonify({
                "service": "email-verification-api",
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }), 503
    
    if Config.monitoring.METRICS_ENABLED:
        @app.route('/metrics')
        def metrics():
            """
            Prometheus Metrics Endpoint
            ---
            tags:
              - Monitoring
            responses:
              200:
                description: Prometheus metrics
            """
            return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}
    
    # Cleanup on shutdown
    @app.teardown_appcontext
    def cleanup(error):
        if hasattr(g, 'verifier'):
            g.verifier.cleanup()
    
    logger.info(f"Flask application initialized successfully (Environment: {Config.ENV})")
    return app

# Create the Flask application
app = create_app()

if __name__ == '__main__':
    logger.info(f"Starting Email Verification API v{Config.api.VERSION}")
    logger.info(f"Environment: {Config.ENV}")
    logger.info(f"Debug mode: {Config.DEBUG}")
    logger.info(f"Host: {Config.HOST}:{Config.PORT}")
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        threaded=True
    )
