import os
import logging
from typing import Optional
from dataclasses import dataclass, field
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
    REQUIRE_AUTH: bool = os.getenv("REQUIRE_AUTH", "false").lower() == "true"
    ALLOWED_ORIGINS: list = field(default_factory=lambda: os.getenv("ALLOWED_ORIGINS", "*").split(","))

@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    STORAGE_URI: str = os.getenv("RATE_LIMIT_STORAGE", "redis://localhost:6379/1")
    DEFAULT_LIMIT: str = os.getenv("DEFAULT_RATE_LIMIT", "1000 per hour")
    VERIFY_LIMIT: str = os.getenv("VERIFY_RATE_LIMIT", "100 per minute")
    BULK_LIMIT: str = os.getenv("BULK_RATE_LIMIT", "10 per minute")

@dataclass
class SMTPConfig:
    """SMTP verification settings"""
    TIMEOUT: int = int(os.getenv("SMTP_TIMEOUT", "10"))
    FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "verify@localhost")
    POOL_SIZE: int = int(os.getenv("SMTP_POOL_SIZE", "10"))
    RETRIES: int = int(os.getenv("SMTP_RETRIES", "3"))

@dataclass
class APIConfig:
    """API server configuration"""
    ENV: str = os.getenv("ENV", "development")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "5000"))
    WORKERS: int = int(os.getenv("WORKERS", "4"))

@dataclass
class MonitoringConfig:
    """Monitoring and logging configuration"""
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = os.getenv("LOG_FORMAT", "json")
    SENTRY_DSN: Optional[str] = os.getenv("SENTRY_DSN")
    PROMETHEUS_ENABLED: bool = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"
    METRICS_PORT: int = int(os.getenv("METRICS_PORT", "9090"))

@dataclass
class Config:
    """Main configuration class"""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    smtp: SMTPConfig = field(default_factory=SMTPConfig)
    api: APIConfig = field(default_factory=APIConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)

    def __post_init__(self):
        """Validate configuration after initialization"""
        self._setup_logging()
        self._validate_config()

    def _setup_logging(self):
        """Configure logging based on settings"""
        level = getattr(logging, self.monitoring.LOG_LEVEL.upper(), logging.INFO)
        
        if self.monitoring.LOG_FORMAT == "json":
            format_string = '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s", "module": "%(module)s", "function": "%(funcName)s", "line": %(lineno)d}'
        else:
            format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        logging.basicConfig(
            level=level,
            format=format_string,
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def _validate_config(self):
        """Validate configuration settings"""
        logger = logging.getLogger(__name__)
        
        # Validate security settings
        if self.security.REQUIRE_AUTH and not self.security.API_KEY:
            logger.warning("REQUIRE_AUTH is enabled but no API_KEY is set. Authentication will be disabled.")
            self.security.REQUIRE_AUTH = False
        
        # Validate API settings
        if self.api.PORT < 1 or self.api.PORT > 65535:
            logger.warning(f"Invalid port {self.api.PORT}, using default 5000")
            self.api.PORT = 5000
        
        # Log configuration summary
        logger.info(f"Configuration loaded - Environment: {self.api.ENV}")
        logger.info(f"Authentication required: {self.security.REQUIRE_AUTH}")
        logger.info(f"Redis URL: {self.database.REDIS_URL}")
        logger.info(f"Server: {self.api.HOST}:{self.api.PORT}")

# Global configuration instance
Config = Config()
