import os
import logging
from typing import Optional
from dataclasses import dataclass
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

@dataclass
class DatabaseConfig:
    """Database configuration settings"""
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    REDIS_PASSWORD: Optional[str] = os.getenv("REDIS_PASSWORD")
    REDIS_TIMEOUT: int = int(os.getenv("REDIS_TIMEOUT", "5"))
    CACHE_TTL: int = int(os.getenv("CACHE_TTL", "3600"))  # 1 hour

@dataclass
class SecurityConfig:
    """Security and authentication settings"""
    API_KEY: str = os.getenv("API_KEY", "")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    JWT_EXPIRATION_HOURS: int = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))
    REQUIRE_AUTH: bool = os.getenv("REQUIRE_AUTH", "true").lower() == "true"
    ALLOWED_ORIGINS: list = os.getenv("ALLOWED_ORIGINS", "*").split(",")
    MAX_CONTENT_LENGTH: int = int(os.getenv("MAX_CONTENT_LENGTH", "1048576"))  # 1MB

@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    DEFAULT_LIMIT: str = os.getenv("RATE_LIMIT_DEFAULT", "1000 per hour")
    VERIFY_LIMIT: str = os.getenv("RATE_LIMIT_VERIFY", "100 per minute")
    BULK_LIMIT: str = os.getenv("RATE_LIMIT_BULK", "10 per minute")
    STORAGE_URI: str = os.getenv("RATE_LIMIT_STORAGE", "redis://localhost:6379/1")

@dataclass
class SMTPConfig:
    """SMTP verification settings"""
    TIMEOUT: int = int(os.getenv("SMTP_TIMEOUT", "10"))
    MAX_RETRIES: int = int(os.getenv("SMTP_MAX_RETRIES", "3"))
    FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "verify@emailvalidator.com")
    POOL_SIZE: int = int(os.getenv("SMTP_POOL_SIZE", "10"))
    CONNECTION_TIMEOUT: int = int(os.getenv("SMTP_CONNECTION_TIMEOUT", "30"))

@dataclass
class APIConfig:
    """API configuration settings"""
    TITLE: str = "Email Verification API"
    VERSION: str = "2.0.0"
    DESCRIPTION: str = "Production-ready email verification and validation service"
    OPENAPI_VERSION: str = "3.0.3"
    MAX_BULK_SIZE: int = int(os.getenv("MAX_BULK_SIZE", "100"))
    ENABLE_SWAGGER: bool = os.getenv("ENABLE_SWAGGER", "true").lower() == "true"

@dataclass
class MonitoringConfig:
    """Monitoring and logging configuration"""
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = os.getenv("LOG_FORMAT", "json")
    METRICS_ENABLED: bool = os.getenv("METRICS_ENABLED", "true").lower() == "true"
    HEALTH_CHECK_TIMEOUT: int = int(os.getenv("HEALTH_CHECK_TIMEOUT", "5"))
    SENTRY_DSN: Optional[str] = os.getenv("SENTRY_DSN")

class Config:
    """Main configuration class combining all settings"""
    
    # Environment
    ENV: str = os.getenv("ENV", "development")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "5000"))
    WORKERS: int = int(os.getenv("WORKERS", "4"))
    
    # Component configurations
    database = DatabaseConfig()
    security = SecurityConfig()
    rate_limit = RateLimitConfig()
    smtp = SMTPConfig()
    api = APIConfig()
    monitoring = MonitoringConfig()
    
    @classmethod
    def validate(cls) -> bool:
        """Validate configuration settings"""
        errors = []
        
        # Required settings for production
        if cls.ENV == "production":
            if not cls.security.API_KEY:
                errors.append("API_KEY is required in production")
            if not cls.security.JWT_SECRET_KEY:
                errors.append("JWT_SECRET_KEY is required in production")
            if cls.DEBUG:
                errors.append("DEBUG should be False in production")
        
        # Validate ports
        if not (1 <= cls.PORT <= 65535):
            errors.append(f"Invalid PORT: {cls.PORT}")
        
        # Validate worker count
        if cls.WORKERS < 1:
            errors.append(f"WORKERS must be >= 1, got {cls.WORKERS}")
        
        if errors:
            for error in errors:
                logging.error(f"Configuration error: {error}")
            return False
        
        return True
    
    @classmethod
    def setup_logging(cls):
        """Setup logging configuration"""
        log_level = getattr(logging, cls.monitoring.LOG_LEVEL.upper(), logging.INFO)
        
        if cls.monitoring.LOG_FORMAT == "json":
            import json
            import sys
            
            class JSONFormatter(logging.Formatter):
                def format(self, record):
                    log_entry = {
                        "timestamp": self.formatTime(record),
                        "level": record.levelname,
                        "logger": record.name,
                        "message": record.getMessage(),
                        "module": record.module,
                        "function": record.funcName,
                        "line": record.lineno
                    }
                    if record.exc_info:
                        log_entry["exception"] = self.formatException(record.exc_info)
                    return json.dumps(log_entry)
            
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(JSONFormatter())
        else:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
        
        # Configure root logger
        logging.root.setLevel(log_level)
        logging.root.addHandler(handler)
        
        # Set specific loggers
        logging.getLogger("flask").setLevel(log_level)
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
    
    @classmethod
    def is_production(cls) -> bool:
        """Check if running in production environment"""
        return cls.ENV.lower() == "production"
    
    @classmethod
    def is_development(cls) -> bool:
        """Check if running in development environment"""
        return cls.ENV.lower() == "development"
