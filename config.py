import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    API_TITLE = "Email Verification API"
    API_VERSION = "1.0"
    OPENAPI_VERSION = "3.0.3"
    API_KEY = os.getenv("API_KEY", "default-secret-key")
    REQUIRED_API_KEY = True
    RATELIMIT_DEFAULT = "10000 per day"
    SMTP_TIMEOUT = 10
    SMTP_FROM_EMAIL = "verify@emailverifier.com"
