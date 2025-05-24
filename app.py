
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from auth import api_key_required
from verifier import EmailVerifier
from config import Config

app = Flask(__name__)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATELIMIT_DEFAULT]
)

@app.route('/verify', methods=['POST'])
@api_key_required
@limiter.limit("10 per minute")
def verify_email():
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({
            "success": False,
            "message": "Email parameter is required"
        }), 400
    
    verifier = EmailVerifier()
    result = verifier.verify_email(data['email'])
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)