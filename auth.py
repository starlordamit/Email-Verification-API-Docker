from functools import wraps
from flask import request, jsonify
from config import Config

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not Config.REQUIRED_API_KEY:
            return f(*args, **kwargs)
            
        api_key = request.headers.get('X-API-KEY')
        if api_key != Config.API_KEY:
            return jsonify({
                "success": False,
                "message": "Invalid API Key"
            }), 401
        return f(*args, **kwargs)
    return decorated_function
