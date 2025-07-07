from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from verifier import EmailVerifier
from config import Config
import os

app = Flask(__name__)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATELIMIT_DEFAULT]
)

# Initialize the email verifier
verifier = EmailVerifier(from_email=os.environ.get('SENDER_EMAIL', 'verify@example.com'))

@app.route('/')
def index():
    return jsonify({
        "service": "Email Verification API",
        "status": "running",
        "usage": "/api/verify?email=example@domain.com"
    })

@app.route('/api/verify', methods=['GET'])
@limiter.limit("100 per minute")
def verify_email():
    email = request.args.get('email')
    
    if not email:
        return jsonify({
            "success": False,
            "message": "Email parameter is required"
        }), 400
    
    try:
        result = verifier.verify_email(email)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error verifying email: {str(e)}"
        }), 500

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'False').lower() == 'true')
