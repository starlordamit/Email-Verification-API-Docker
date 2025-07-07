#!/usr/bin/env python3
"""
Simplified Email Verification API for Testing
Production-ready email verification without Redis dependencies
"""

import os
from flask import Flask, jsonify, request
from flask_cors import CORS
import logging
import sys
import traceback
from datetime import datetime
import json

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our modules
from verifier import EmailVerifier
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app():
    """Create Flask app without Redis dependencies"""
    app = Flask(__name__)
    
    # Enable CORS
    CORS(app, origins=["*"])
    
    # Initialize email verifier without Redis
    verifier = EmailVerifier()
    
    @app.route('/')
    def root():
        """API information endpoint"""
        return jsonify({
            "name": "Email Verification API v2.0",
            "version": "2.0.0",
            "status": "running",
            "description": "Production-ready email verification service",
            "features": [
                "Single email verification",
                "Bulk email verification",
                "SMTP validation",
                "Domain validation",
                "Security analysis"
            ],
            "endpoints": {
                "health": "/health",
                "verify": "/api/v2/verify",
                "bulk_verify": "/api/v2/bulk-verify",
                "docs": "/api/docs/"
            }
        })
    
    @app.route('/health')
    def health():
        """Health check endpoint"""
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "2.0.0",
            "services": {
                "email_verifier": "online",
                "redis": "offline (not required for testing)",
                "api": "running"
            }
        })
    
    @app.route('/api/v2/verify', methods=['POST'])
    def verify_email():
        """Single email verification endpoint"""
        try:
            data = request.get_json()
            if not data or 'email' not in data:
                return jsonify({
                    "error": "Missing email field",
                    "message": "Request must include 'email' field"
                }), 400
            
            email = data['email']
            if not email or not isinstance(email, str):
                return jsonify({
                    "error": "Invalid email",
                    "message": "Email must be a non-empty string"
                }), 400
            
            # Verify email
            result = verifier.verify_email(email)
            
            return jsonify({
                "email": email,
                "result": result.__dict__,
                "timestamp": datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error verifying email: {e}")
            return jsonify({
                "error": "verification_failed",
                "message": str(e)
            }), 500
    
    @app.route('/api/v2/bulk-verify', methods=['POST'])
    def bulk_verify():
        """Bulk email verification endpoint"""
        try:
            data = request.get_json()
            if not data or 'emails' not in data:
                return jsonify({
                    "error": "Missing emails field",
                    "message": "Request must include 'emails' field"
                }), 400
            
            emails = data['emails']
            if not isinstance(emails, list) or len(emails) == 0:
                return jsonify({
                    "error": "Invalid emails",
                    "message": "Emails must be a non-empty list"
                }), 400
            
            if len(emails) > 100:
                return jsonify({
                    "error": "Too many emails",
                    "message": "Maximum 100 emails per request"
                }), 400
            
            # Verify all emails
            results = []
            for email in emails:
                if isinstance(email, str) and email.strip():
                    result = verifier.verify_email(email.strip())
                    results.append({
                        "email": email.strip(),
                        "result": result.__dict__
                    })
                else:
                    results.append({
                        "email": str(email),
                        "result": {
                            "is_valid": False,
                            "is_deliverable": False,
                            "is_role_account": False,
                            "is_disposable": False,
                            "confidence_score": 0.0,
                            "errors": ["Invalid email format"]
                        }
                    })
            
            return jsonify({
                "total_processed": len(results),
                "results": results,
                "timestamp": datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error in bulk verification: {e}")
            return jsonify({
                "error": "bulk_verification_failed",
                "message": str(e)
            }), 500
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors"""
        return jsonify({
            "error": "not_found",
            "message": "Endpoint not found",
            "timestamp": datetime.utcnow().isoformat()
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors"""
        logger.error(f"Internal server error: {error}")
        return jsonify({
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "timestamp": datetime.utcnow().isoformat()
        }), 500
    
    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.getenv('PORT', 8080))
    
    logger.info(f"🚀 Starting Email Verification API v2.0 on port {port}")
    logger.info("⚡ Production-ready email verification service")
    logger.info("🔧 Running in test mode (Redis not required)")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=os.getenv('DEBUG', 'false').lower() == 'true'
    ) 