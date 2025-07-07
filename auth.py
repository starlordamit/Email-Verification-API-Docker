#!/usr/bin/env python3
"""
Simplified Authentication System for Email Verification API
Simple API key based authentication from environment variables
"""

import os
import logging
from functools import wraps
from flask import request, jsonify, g
from datetime import datetime

logger = logging.getLogger(__name__)

class SimpleAuth:
    """Simple API key authentication"""
    
    def __init__(self):
        self.api_key = os.getenv('API_KEY', '')
        self.require_auth = os.getenv('REQUIRE_AUTH', 'false').lower() == 'true'
        
        if self.require_auth and not self.api_key:
            logger.warning("API_KEY not set but REQUIRE_AUTH is enabled. API will be open to all requests.")
            self.require_auth = False
    
    def verify_api_key(self, provided_key: str) -> bool:
        """Verify the provided API key"""
        if not self.require_auth:
            return True
            
        if not self.api_key:
            return True
            
        return provided_key == self.api_key
    
    def get_api_key_from_request(self) -> str:
        """Extract API key from request headers"""
        # Try different header formats
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            api_key = request.headers.get('Authorization')
            if api_key and api_key.startswith('Bearer '):
                api_key = api_key[7:]  # Remove 'Bearer ' prefix
        
        return api_key or ''

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = SimpleAuth()
        
        # Skip authentication if not required
        if not auth.require_auth:
            g.authenticated = True
            g.api_key_used = None
            return f(*args, **kwargs)
        
        # Get API key from request
        provided_key = auth.get_api_key_from_request()
        
        # Verify API key
        if not auth.verify_api_key(provided_key):
            logger.warning(f"Invalid API key attempt from {request.remote_addr}")
            return jsonify({
                'success': False,
                'error': 'Invalid or missing API key',
                'message': 'Please provide a valid API key in X-API-Key header or Authorization: Bearer <key>',
                'timestamp': datetime.now().isoformat()
            }), 401
        
        # Store authentication info in request context
        g.authenticated = True
        g.api_key_used = provided_key if provided_key else None
        
        # Log successful authentication
        if provided_key:
            logger.info(f"API key authentication successful from {request.remote_addr}")
        
        return f(*args, **kwargs)
    
    return decorated_function

def optional_api_key(f):
    """Decorator for optional API key authentication (doesn't block if missing)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = SimpleAuth()
        provided_key = auth.get_api_key_from_request()
        
        # Store authentication info in request context
        g.authenticated = auth.verify_api_key(provided_key)
        g.api_key_used = provided_key if provided_key else None
        
        return f(*args, **kwargs)
    
    return decorated_function

def get_auth_info() -> dict:
    """Get authentication information for current request"""
    auth = SimpleAuth()
    return {
        'authenticated': getattr(g, 'authenticated', False),
        'api_key_provided': bool(getattr(g, 'api_key_used', '')),
        'auth_required': auth.require_auth
    }
