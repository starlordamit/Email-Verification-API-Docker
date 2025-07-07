import jwt
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Dict, Any
from flask import request, jsonify, g
from werkzeug.security import check_password_hash, generate_password_hash
from config import Config

logger = logging.getLogger(__name__)

class AuthenticationError(Exception):
    """Custom authentication exception"""
    pass

class AuthorizationError(Exception):
    """Custom authorization exception"""
    pass

class SecurityManager:
    """Handles authentication and authorization logic"""
    
    def __init__(self, config: Config):
        self.config = config
        self.valid_api_keys = self._load_api_keys()
    
    def _load_api_keys(self) -> Dict[str, Dict[str, Any]]:
        """Load valid API keys with their associated metadata"""
        # In production, this would come from a database
        api_keys = {}
        
        if self.config.security.API_KEY:
            api_keys[self.config.security.API_KEY] = {
                "name": "default",
                "role": "admin",
                "rate_limit": "unlimited",
                "created_at": datetime.now(),
                "active": True
            }
        
        return api_keys
    
    def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key and return metadata"""
        if not api_key:
            return None
        
        key_info = self.valid_api_keys.get(api_key)
        if not key_info or not key_info.get("active"):
            return None
        
        return key_info
    
    def generate_jwt_token(self, payload: Dict[str, Any]) -> str:
        """Generate JWT token with expiration"""
        if not self.config.security.JWT_SECRET_KEY:
            raise AuthenticationError("JWT secret key not configured")
        
        # Add standard claims
        now = datetime.utcnow()
        payload.update({
            "iat": now,
            "exp": now + timedelta(hours=self.config.security.JWT_EXPIRATION_HOURS),
            "iss": "email-verification-api"
        })
        
        return jwt.encode(
            payload, 
            self.config.security.JWT_SECRET_KEY, 
            algorithm="HS256"
        )
    
    def validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token and return payload"""
        try:
            payload = jwt.decode(
                token, 
                self.config.security.JWT_SECRET_KEY, 
                algorithms=["HS256"],
                options={"verify_exp": True}
            )
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            return None
    
    def check_rate_limit_permission(self, user_info: Dict[str, Any], endpoint: str) -> bool:
        """Check if user has permission for specific rate limits"""
        user_role = user_info.get("role", "user")
        
        # Admin users have unlimited access
        if user_role == "admin":
            return True
        
        # Premium users have higher limits
        if user_role == "premium":
            return True
        
        # Regular users have standard limits
        return True

# Initialize security manager
security_manager = SecurityManager(Config)

def extract_auth_info() -> Optional[Dict[str, Any]]:
    """Extract authentication information from request"""
    # Try API key first
    api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
    
    if api_key and not api_key.startswith("Bearer "):
        # Regular API key
        key_info = security_manager.validate_api_key(api_key)
        if key_info:
            return {
                "type": "api_key",
                "user_id": key_info["name"],
                "role": key_info["role"],
                "metadata": key_info
            }
    
    # Try JWT token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]  # Remove "Bearer " prefix
        payload = security_manager.validate_jwt_token(token)
        if payload:
            return {
                "type": "jwt",
                "user_id": payload.get("user_id"),
                "role": payload.get("role", "user"),
                "metadata": payload
            }
    
    return None

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not Config.security.REQUIRE_AUTH:
            # Authentication disabled
            g.current_user = {
                "type": "anonymous",
                "user_id": "anonymous",
                "role": "user",
                "metadata": {}
            }
            return f(*args, **kwargs)
        
        auth_info = extract_auth_info()
        if not auth_info:
            logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
            return jsonify({
                "error": "unauthorized",
                "message": "Valid authentication required",
                "code": 401
            }), 401
        
        # Store user info in request context
        g.current_user = auth_info
        
        logger.info(f"Authenticated request from user {auth_info['user_id']} with role {auth_info['role']}")
        return f(*args, **kwargs)
    
    return decorated_function

def require_role(required_role: str):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user') or not g.current_user:
                return jsonify({
                    "error": "unauthorized", 
                    "message": "Authentication required",
                    "code": 401
                }), 401
            
            user_role = g.current_user.get("role", "user")
            
            # Role hierarchy: admin > premium > user
            role_hierarchy = {"admin": 3, "premium": 2, "user": 1}
            
            required_level = role_hierarchy.get(required_role, 1)
            user_level = role_hierarchy.get(user_role, 1)
            
            if user_level < required_level:
                logger.warning(f"Insufficient permissions: user {g.current_user['user_id']} "
                             f"(role: {user_role}) attempted to access {required_role} endpoint")
                return jsonify({
                    "error": "forbidden",
                    "message": f"Role '{required_role}' required",
                    "code": 403
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def api_key_required(f):
    """Legacy decorator for backward compatibility"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return require_auth(f)(*args, **kwargs)
    return decorated_function

def validate_request_data(schema):
    """Decorator to validate request data against schema"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                if request.is_json:
                    data = request.get_json()
                else:
                    data = request.form.to_dict()
                
                # Validate against schema (using marshmallow or pydantic)
                validated_data = schema.load(data) if hasattr(schema, 'load') else schema(**data)
                g.validated_data = validated_data
                
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Request validation error: {e}")
                return jsonify({
                    "error": "validation_error",
                    "message": str(e),
                    "code": 400
                }), 400
        
        return decorated_function
    return decorator

def log_request(f):
    """Decorator to log request details for security monitoring"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_info = getattr(g, 'current_user', {})
        
        log_data = {
            "endpoint": request.endpoint,
            "method": request.method,
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "user_id": user_info.get("user_id", "anonymous"),
            "role": user_info.get("role", "unknown"),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        logger.info(f"API Request: {log_data}")
        
        try:
            response = f(*args, **kwargs)
            return response
        except Exception as e:
            logger.error(f"Request failed: {log_data} - Error: {str(e)}")
            raise
    
    return decorated_function

class AuthTokenManager:
    """Manages authentication tokens for API access"""
    
    @staticmethod
    def create_api_token(user_id: str, role: str = "user", expires_hours: int = 24) -> str:
        """Create a new API token"""
        payload = {
            "user_id": user_id,
            "role": role,
            "token_type": "api_access"
        }
        return security_manager.generate_jwt_token(payload)
    
    @staticmethod
    def revoke_token(token: str) -> bool:
        """Revoke a token (in production, store in blacklist)"""
        # In production, add to Redis blacklist
        logger.info(f"Token revoked: {token[:20]}...")
        return True
