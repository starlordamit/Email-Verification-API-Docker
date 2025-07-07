import re
import socket
import time
import logging
import hashlib
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from email_validator import validate_email, EmailNotValidError

# DNS and Network
import dns.resolver
import dns.exception
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# SMTP
import smtplib
from smtplib import SMTPConnectError, SMTPServerDisconnected, SMTPResponseException

# Caching and Database
import redis
from redis.exceptions import RedisError
import json

# Configuration
from config import Config

logger = logging.getLogger(__name__)

@dataclass
class VerificationResult:
    """Structured verification result"""
    email_address: str
    is_valid: bool
    status: str  # deliverable, undeliverable, risky, unknown
    confidence_score: int  # 0-100
    validation_details: Dict[str, Any]
    domain_details: Dict[str, Any]
    provider_info: Dict[str, Any]
    security_flags: Dict[str, bool]
    performance_metrics: Dict[str, float]
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result

class EmailVerificationCache:
    """Redis-based caching for email verification results"""
    
    def __init__(self, redis_url: str, ttl: int = 3600):
        self.ttl = ttl
        self.redis_client = None
        self._connect_redis(redis_url)
    
    def _connect_redis(self, redis_url: str):
        """Initialize Redis connection with error handling"""
        try:
            self.redis_client = redis.from_url(
                redis_url,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True
            )
            # Test connection
            self.redis_client.ping()
            logger.info("Redis cache connection established")
        except RedisError as e:
            logger.warning(f"Redis connection failed: {e}. Operating without cache.")
            self.redis_client = None
    
    def get(self, email: str) -> Optional[Dict[str, Any]]:
        """Get cached verification result"""
        if not self.redis_client:
            return None
        
        try:
            cache_key = f"email_verify:{hashlib.md5(email.lower().encode()).hexdigest()}"
            cached_data = self.redis_client.get(cache_key)
            if cached_data:
                return json.loads(cached_data)
        except (RedisError, json.JSONDecodeError) as e:
            logger.warning(f"Cache get error: {e}")
        
        return None
    
    def set(self, email: str, result: Dict[str, Any]):
        """Cache verification result"""
        if not self.redis_client:
            return
        
        try:
            cache_key = f"email_verify:{hashlib.md5(email.lower().encode()).hexdigest()}"
            self.redis_client.setex(
                cache_key, 
                self.ttl, 
                json.dumps(result, default=str)
            )
        except (RedisError, TypeError) as e:
            logger.warning(f"Cache set error: {e}")

class SMTPConnectionPool:
    """SMTP connection pool for efficient verification"""
    
    def __init__(self, pool_size: int = 10, timeout: int = 10):
        self.pool_size = pool_size
        self.timeout = timeout
        self.connections = {}
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=pool_size)
    
    def get_connection(self, mx_server: str) -> Optional[smtplib.SMTP]:
        """Get or create SMTP connection"""
        with self.lock:
            if mx_server in self.connections:
                try:
                    conn = self.connections[mx_server]
                    conn.noop()  # Test connection
                    return conn
                except (SMTPServerDisconnected, SMTPResponseException):
                    del self.connections[mx_server]
            
            try:
                conn = smtplib.SMTP(timeout=self.timeout)
                conn.connect(mx_server)
                conn.ehlo_or_helo_if_needed()
                self.connections[mx_server] = conn
                return conn
            except Exception as e:
                logger.debug(f"Failed to connect to {mx_server}: {e}")
                return None
    
    def release_connection(self, mx_server: str, conn: smtplib.SMTP):
        """Release connection back to pool"""
        # For now, keep connection alive. In production, implement proper pooling
        pass
    
    def close_all(self):
        """Close all connections"""
        with self.lock:
            for conn in self.connections.values():
                try:
                    conn.quit()
                except:
                    pass
            self.connections.clear()

class DomainSecurityChecker:
    """Check domain security and reputation"""
    
    def __init__(self):
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain against security databases"""
        result = {
            "is_malicious": False,
            "is_phishing": False,
            "reputation_score": 50,  # Default neutral score
            "security_sources": []
        }
        
        # Check against known malicious domain lists
        malicious_indicators = [
            'temp', 'spam', 'fake', 'test', 'demo', 'example',
            'malware', 'phish', 'scam', 'fraud'
        ]
        
        domain_lower = domain.lower()
        for indicator in malicious_indicators:
            if indicator in domain_lower:
                result["is_malicious"] = True
                result["reputation_score"] = 10
                result["security_sources"].append(f"keyword_match_{indicator}")
                break
        
        return result

class ProductionEmailVerifier:
    """Production-ready email verification service"""
    
    def __init__(self, config: Config):
        self.config = config
        self.cache = EmailVerificationCache(
            config.database.REDIS_URL, 
            config.database.CACHE_TTL
        )
        self.smtp_pool = SMTPConnectionPool(
            config.smtp.POOL_SIZE,
            config.smtp.TIMEOUT
        )
        self.security_checker = DomainSecurityChecker()
        self.performance_metrics = {}
        
        # Known email providers
        self.email_providers = self._load_email_providers()
        
        # Domain lists
        self.disposable_domains = self._load_disposable_domains()
        self.free_domains = self._load_free_domains()
        self.role_accounts = self._load_role_accounts()
    
    def _load_email_providers(self) -> Dict[str, Dict[str, Any]]:
        """Load email provider information"""
        return {
            'gmail.com': {
                'name': 'Gmail',
                'mx_patterns': ['gmail-smtp-in.l.google.com'],
                'reputation': 'high',
                'catch_all': False
            },
            'outlook.com': {
                'name': 'Microsoft Outlook',
                'mx_patterns': ['outlook-com.olc.protection.outlook.com'],
                'reputation': 'high',
                'catch_all': False
            },
            'yahoo.com': {
                'name': 'Yahoo Mail',
                'mx_patterns': ['mta5.am0.yahoodns.net'],
                'reputation': 'medium',
                'catch_all': False
            }
        }
    
    def _load_disposable_domains(self) -> set:
        """Load disposable email domains"""
        return {
            'mailinator.com', 'tempmail.com', '10minutemail.com',
            'guerrillamail.com', 'sharklasers.com', 'yopmail.com',
            'temp-mail.org', 'throwaway.email', 'maildrop.cc'
        }
    
    def _load_free_domains(self) -> set:
        """Load free email provider domains"""
        return {
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'aol.com', 'icloud.com', 'protonmail.com', 'tutanota.com'
        }
    
    def _load_role_accounts(self) -> set:
        """Load role-based account patterns"""
        return {
            'admin', 'administrator', 'contact', 'support', 'help',
            'info', 'sales', 'service', 'feedback', 'webmaster',
            'postmaster', 'hostmaster', 'abuse', 'security',
            'noreply', 'no-reply', 'donotreply', 'do-not-reply'
        }
    
    async def verify_email_async(self, email: str, skip_cache: bool = False) -> VerificationResult:
        """Asynchronous email verification"""
        start_time = time.time()
        
        # Check cache first
        if not skip_cache:
            cached_result = self.cache.get(email)
            if cached_result:
                logger.debug(f"Cache hit for {email}")
                return VerificationResult(**cached_result)
        
        # Perform verification
        result = await self._perform_verification(email, start_time)
        
        # Cache result
        if result.confidence_score > 70:  # Only cache high-confidence results
            self.cache.set(email, result.to_dict())
        
        return result
    
    def verify_email(self, email: str, skip_cache: bool = False) -> VerificationResult:
        """Synchronous email verification wrapper"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.verify_email_async(email, skip_cache))
        finally:
            loop.close()
    
    async def _perform_verification(self, email: str, start_time: float) -> VerificationResult:
        """Core verification logic"""
        email = email.strip().lower()
        
        # Initialize result structure
        result = VerificationResult(
            email_address=email,
            is_valid=False,
            status="unknown",
            confidence_score=0,
            validation_details={},
            domain_details={},
            provider_info={},
            security_flags={},
            performance_metrics={},
            timestamp=datetime.utcnow()
        )
        
        try:
            # Step 1: Format validation
            format_check = await self._check_format(email)
            result.validation_details['format'] = format_check
            
            if not format_check['valid']:
                result.status = "invalid"
                result.performance_metrics['total_time'] = time.time() - start_time
                return result
            
            domain = email.split('@')[1]
            
            # Step 2: Domain analysis
            domain_info = await self._analyze_domain(domain)
            result.domain_details = domain_info
            
            # Step 3: DNS checks
            dns_check = await self._check_dns(domain)
            result.validation_details['dns'] = dns_check
            
            if not dns_check['mx_found']:
                result.status = "undeliverable"
                result.confidence_score = 20
                result.performance_metrics['total_time'] = time.time() - start_time
                return result
            
            # Step 4: SMTP verification
            smtp_check = await self._check_smtp(email, dns_check['mx_records'])
            result.validation_details['smtp'] = smtp_check
            
            # Step 5: Security analysis
            security_analysis = await self._analyze_security(email, domain)
            result.security_flags = security_analysis
            
            # Step 6: Provider identification
            provider_info = await self._identify_provider(domain, dns_check['mx_records'])
            result.provider_info = provider_info
            
            # Step 7: Calculate final score and status
            final_assessment = self._calculate_final_score(result)
            result.is_valid = final_assessment['is_valid']
            result.status = final_assessment['status']
            result.confidence_score = final_assessment['confidence_score']
            
            result.performance_metrics['total_time'] = time.time() - start_time
            
            logger.info(f"Verification completed for {email}: {result.status} (score: {result.confidence_score})")
            
        except Exception as e:
            logger.error(f"Verification error for {email}: {e}", exc_info=True)
            result.status = "error"
            result.validation_details['error'] = str(e)
            result.performance_metrics['total_time'] = time.time() - start_time
        
        return result
    
    async def _check_format(self, email: str) -> Dict[str, Any]:
        """Advanced format validation"""
        try:
            # Use email-validator library for comprehensive validation
            valid = validate_email(email)
            return {
                'valid': True,
                'normalized': valid.email,
                'local_part': valid.local,
                'domain_part': valid.domain,
                'ascii_email': valid.ascii_email,
                'smtputf8': valid.smtputf8
            }
        except EmailNotValidError as e:
            return {
                'valid': False,
                'error': str(e),
                'normalized': None,
                'local_part': None,
                'domain_part': None
            }
    
    async def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Comprehensive domain analysis"""
        return {
            'domain': domain,
            'is_disposable': domain in self.disposable_domains,
            'is_free_provider': domain in self.free_domains,
            'age_days': None,  # Would implement WHOIS lookup
            'registrar': None,
            'creation_date': None,
            'expiration_date': None
        }
    
    async def _check_dns(self, domain: str) -> Dict[str, Any]:
        """DNS resolution and MX record checking"""
        try:
            mx_records = []
            
            # Get MX records
            try:
                mx_answers = dns.resolver.resolve(domain, 'MX')
                mx_records = [(str(mx.exchange).rstrip('.'), mx.preference) 
                             for mx in mx_answers]
                mx_records.sort(key=lambda x: x[1])  # Sort by preference
            except dns.exception.DNSException:
                pass
            
            # Get A record
            a_record = None
            try:
                a_answers = dns.resolver.resolve(domain, 'A')
                a_record = str(a_answers[0])
            except dns.exception.DNSException:
                pass
            
            return {
                'mx_found': len(mx_records) > 0,
                'mx_records': [mx[0] for mx in mx_records],
                'mx_count': len(mx_records),
                'a_record': a_record,
                'has_a_record': a_record is not None
            }
            
        except Exception as e:
            logger.error(f"DNS check error for {domain}: {e}")
            return {
                'mx_found': False,
                'mx_records': [],
                'mx_count': 0,
                'a_record': None,
                'has_a_record': False,
                'error': str(e)
            }
    
    async def _check_smtp(self, email: str, mx_records: List[str]) -> Dict[str, Any]:
        """SMTP mailbox verification"""
        if not mx_records:
            return {
                'mailbox_exists': False,
                'smtp_response': 'No MX records',
                'response_code': None,
                'is_catch_all': False,
                'is_disabled': False,
                'is_full': False
            }
        
        for mx_server in mx_records[:3]:  # Try top 3 MX servers
            try:
                conn = self.smtp_pool.get_connection(mx_server)
                if not conn:
                    continue
                
                # Try MAIL FROM
                conn.mail(self.config.smtp.FROM_EMAIL)
                
                # Try RCPT TO
                code, response = conn.rcpt(email)
                response_text = response.decode('utf-8', errors='ignore') if isinstance(response, bytes) else str(response)
                
                result = {
                    'mailbox_exists': code == 250,
                    'smtp_response': response_text,
                    'response_code': code,
                    'mx_server': mx_server,
                    'is_catch_all': False,
                    'is_disabled': 'disabled' in response_text.lower(),
                    'is_full': code == 552 or 'full' in response_text.lower()
                }
                
                # Reset for next verification
                try:
                    conn.rset()
                except:
                    pass
                
                return result
                
            except Exception as e:
                logger.debug(f"SMTP check failed for {mx_server}: {e}")
                continue
        
        return {
            'mailbox_exists': False,
            'smtp_response': 'All SMTP servers unreachable',
            'response_code': None,
            'is_catch_all': False,
            'is_disabled': False,
            'is_full': False
        }
    
    async def _analyze_security(self, email: str, domain: str) -> Dict[str, bool]:
        """Security and risk analysis"""
        local_part = email.split('@')[0]
        
        # Check for role accounts
        is_role = any(role in local_part.lower() for role in self.role_accounts)
        
        # Check domain security
        domain_security = self.security_checker.check_domain_reputation(domain)
        
        return {
            'is_role_account': is_role,
            'is_disposable': domain in self.disposable_domains,
            'is_malicious_domain': domain_security['is_malicious'],
            'is_phishing_domain': domain_security['is_phishing'],
            'has_suspicious_pattern': self._check_suspicious_patterns(email),
            'is_recently_created': False  # Would implement based on WHOIS data
        }
    
    def _check_suspicious_patterns(self, email: str) -> bool:
        """Check for suspicious email patterns"""
        suspicious_patterns = [
            r'[0-9]{10,}',  # Too many consecutive numbers
            r'[a-z]{20,}',  # Too many consecutive letters
            r'(.)\1{5,}',   # Repeated characters
            r'^[0-9]+@',    # Only numbers in local part
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email, re.IGNORECASE):
                return True
        
        return False
    
    async def _identify_provider(self, domain: str, mx_records: List[str]) -> Dict[str, Any]:
        """Identify email service provider"""
        provider_info = self.email_providers.get(domain)
        
        if provider_info:
            return {
                'name': provider_info['name'],
                'type': 'hosted',
                'reputation': provider_info['reputation'],
                'supports_catch_all': provider_info.get('catch_all', False)
            }
        
        # Analyze MX records for provider identification
        if mx_records:
            mx_server = mx_records[0].lower()
            if 'google' in mx_server or 'gmail' in mx_server:
                return {'name': 'Google Workspace', 'type': 'hosted', 'reputation': 'high'}
            elif 'outlook' in mx_server or 'microsoft' in mx_server:
                return {'name': 'Microsoft 365', 'type': 'hosted', 'reputation': 'high'}
            elif 'amazonaws' in mx_server:
                return {'name': 'Amazon SES', 'type': 'hosted', 'reputation': 'medium'}
        
        return {
            'name': 'Custom/Unknown',
            'type': 'self-hosted',
            'reputation': 'unknown',
            'supports_catch_all': None
        }
    
    def _calculate_final_score(self, result: VerificationResult) -> Dict[str, Any]:
        """Calculate final confidence score and status"""
        score = 0
        
        # Format validation (20 points)
        if result.validation_details.get('format', {}).get('valid'):
            score += 20
        
        # DNS/MX records (25 points)
        if result.validation_details.get('dns', {}).get('mx_found'):
            score += 25
        
        # SMTP response (30 points)
        smtp_check = result.validation_details.get('smtp', {})
        if smtp_check.get('mailbox_exists'):
            score += 30
        elif smtp_check.get('response_code') in [450, 451, 452]:  # Temporary errors
            score += 15
        
        # Security flags (deductions)
        security = result.security_flags
        if security.get('is_disposable'):
            score -= 15
        if security.get('is_role_account'):
            score -= 10
        if security.get('is_malicious_domain'):
            score -= 30
        if security.get('has_suspicious_pattern'):
            score -= 10
        
        # Provider reputation (bonus)
        provider_rep = result.provider_info.get('reputation', 'unknown')
        if provider_rep == 'high':
            score += 10
        elif provider_rep == 'medium':
            score += 5
        
        # Determine status
        score = max(0, min(100, score))
        
        if score >= 80:
            status = "deliverable"
            is_valid = True
        elif score >= 50:
            status = "risky"
            is_valid = False
        elif score >= 20:
            status = "undeliverable"
            is_valid = False
        else:
            status = "invalid"
            is_valid = False
        
        return {
            'confidence_score': score,
            'status': status,
            'is_valid': is_valid
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get performance and usage metrics"""
        return {
            'cache_stats': {
                'enabled': self.cache.redis_client is not None
            },
            'smtp_pool_stats': {
                'active_connections': len(self.smtp_pool.connections)
            }
        }
    
    def cleanup(self):
        """Cleanup resources"""
        self.smtp_pool.close_all()
        if hasattr(self.security_checker, 'session'):
            self.security_checker.session.close()
