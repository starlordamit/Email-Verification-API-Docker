#!/usr/bin/env python3
"""
Simplified Email Verification API for Testing
"""

import os
from flask import Flask, jsonify, request
from flask_cors import CORS
import logging

# Simple logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_simple_app():
    """Create a simplified Flask app for testing"""
    app = Flask(__name__)
    
    # Enable CORS
    CORS(app)
    
    @app.route('/')
    def index():
        """API root endpoint"""
        return jsonify({
            "name": "Email Verification API v2.0",
            "status": "running",
            "version": "2.0.0",
            "description": "Production-ready email verification service",
            "endpoints": {
                "health": "/health",
                "verify": "/verify",
                "bulk": "/verify/bulk"
            }
        })
    
    @app.route('/health')
    def health():
        """Basic health check"""
        return jsonify({
            "status": "healthy",
            "timestamp": "2024-01-07T20:00:00Z",
            "version": "2.0.0",
            "environment": "development"
        })
    
    @app.route('/verify', methods=['POST'])
    def verify_email():
        """Verify a single email address"""
        try:
            data = request.get_json()
            if not data or 'email' not in data:
                return jsonify({
                    "error": "Email field is required",
                    "status": "error"
                }), 400
            
            email = data['email']
            
            # Simple validation
            is_valid = '@' in email and '.' in email.split('@')[-1]
            
            return jsonify({
                "email": email,
                "is_valid": is_valid,
                "validation": {
                    "syntax": is_valid,
                    "domain": "unknown",
                    "smtp": "skipped"
                },
                "timestamp": "2024-01-07T20:00:00Z"
            })
        
        except Exception as e:
            logger.error(f"Error verifying email: {e}")
            return jsonify({
                "error": "Internal server error",
                "status": "error"
            }), 500
    
    @app.route('/verify/bulk', methods=['POST'])
    def verify_bulk():
        """Verify multiple email addresses"""
        try:
            data = request.get_json()
            if not data or 'emails' not in data:
                return jsonify({
                    "error": "Emails field is required",
                    "status": "error"
                }), 400
            
            emails = data['emails']
            if not isinstance(emails, list):
                return jsonify({
                    "error": "Emails must be a list",
                    "status": "error"
                }), 400
            
            results = []
            for email in emails:
                is_valid = '@' in email and '.' in email.split('@')[-1]
                results.append({
                    "email": email,
                    "is_valid": is_valid,
                    "validation": {
                        "syntax": is_valid,
                        "domain": "unknown",
                        "smtp": "skipped"
                    }
                })
            
            return jsonify({
                "results": results,
                "total": len(emails),
                "timestamp": "2024-01-07T20:00:00Z"
            })
            
        except Exception as e:
            logger.error(f"Error in bulk verification: {e}")
            return jsonify({
                "error": "Internal server error",
                "status": "error"
            }), 500
    
    return app

if __name__ == '__main__':
    app = create_simple_app()
    port = int(os.getenv('PORT', 8080))
    
    logger.info(f"🚀 Starting Simple Email Verification API")
    logger.info(f"📍 Port: {port}")
    logger.info(f"🌐 Access: http://localhost:{port}")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=True
    ) 