import psutil
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from dataclasses import dataclass

# Prometheus metrics
from prometheus_client import Counter, Histogram, Gauge, Info

# Local imports
from config import Config

logger = logging.getLogger(__name__)

@dataclass
class SystemMetrics:
    """System performance metrics"""
    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    network_connections: int
    uptime_seconds: float
    load_average: Optional[float] = None

class HealthMonitor:
    """Comprehensive health monitoring system"""
    
    def __init__(self):
        self.start_time = time.time()
        self._setup_metrics()
    
    def _setup_metrics(self):
        """Setup Prometheus metrics"""
        # System metrics
        self.cpu_usage = Gauge('system_cpu_usage_percent', 'CPU usage percentage')
        self.memory_usage = Gauge('system_memory_usage_percent', 'Memory usage percentage')
        self.disk_usage = Gauge('system_disk_usage_percent', 'Disk usage percentage')
        self.uptime = Gauge('system_uptime_seconds', 'System uptime in seconds')
        
        # Application metrics
        self.app_info = Info('app_info', 'Application information')
        self.app_info.info({
            'version': Config.api.VERSION,
            'environment': Config.ENV,
            'title': Config.api.TITLE
        })
        
        # Database metrics
        self.redis_connections = Gauge('redis_active_connections', 'Active Redis connections')
        self.cache_hits = Counter('cache_hits_total', 'Total cache hits')
        self.cache_misses = Counter('cache_misses_total', 'Total cache misses')
        
        # SMTP metrics
        self.smtp_connections = Gauge('smtp_active_connections', 'Active SMTP connections')
        self.smtp_errors = Counter('smtp_errors_total', 'Total SMTP errors', ['error_type'])
        
        # Verification metrics
        self.verifications_total = Counter('verifications_total', 'Total verifications', ['status', 'provider'])
        self.verification_latency = Histogram('verification_duration_seconds', 'Verification duration')
        
        logger.info("Prometheus metrics initialized")
    
    def get_system_metrics(self) -> SystemMetrics:
        """Collect system performance metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage (root partition)
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            # Network connections
            connections = len(psutil.net_connections())
            
            # Uptime
            uptime = time.time() - self.start_time
            
            # Load average (Unix-like systems only)
            load_avg = None
            try:
                load_avg = psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else None
            except (AttributeError, OSError):
                pass
            
            # Update Prometheus metrics
            self.cpu_usage.set(cpu_percent)
            self.memory_usage.set(memory_percent)
            self.disk_usage.set(disk_percent)
            self.uptime.set(uptime)
            
            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_usage_percent=disk_percent,
                network_connections=connections,
                uptime_seconds=uptime,
                load_average=load_avg
            )
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return SystemMetrics(
                cpu_percent=0.0,
                memory_percent=0.0,
                disk_usage_percent=0.0,
                network_connections=0,
                uptime_seconds=0.0
            )
    
    def check_redis_health(self, redis_client) -> Dict[str, Any]:
        """Check Redis health and performance"""
        if not redis_client:
            return {
                "status": "disabled",
                "connection_pool_size": 0,
                "used_memory": 0,
                "connected_clients": 0
            }
        
        try:
            # Ping test
            start_time = time.time()
            redis_client.ping()
            ping_latency = (time.time() - start_time) * 1000  # Convert to ms
            
            # Get Redis info
            info = redis_client.info()
            
            result = {
                "status": "healthy",
                "ping_latency_ms": ping_latency,
                "used_memory_mb": info.get('used_memory', 0) / (1024 * 1024),
                "connected_clients": info.get('connected_clients', 0),
                "total_commands_processed": info.get('total_commands_processed', 0),
                "keyspace_hits": info.get('keyspace_hits', 0),
                "keyspace_misses": info.get('keyspace_misses', 0),
                "version": info.get('redis_version', 'unknown')
            }
            
            # Calculate hit ratio
            hits = result["keyspace_hits"]
            misses = result["keyspace_misses"]
            if hits + misses > 0:
                result["cache_hit_ratio"] = hits / (hits + misses)
            else:
                result["cache_hit_ratio"] = 0.0
            
            # Update Prometheus metrics
            self.redis_connections.set(result["connected_clients"])
            
            return result
            
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "ping_latency_ms": None
            }
    
    def check_smtp_pool_health(self, smtp_pool) -> Dict[str, Any]:
        """Check SMTP connection pool health"""
        try:
            active_connections = len(smtp_pool.connections) if hasattr(smtp_pool, 'connections') else 0
            
            result = {
                "status": "healthy",
                "active_connections": active_connections,
                "pool_size": smtp_pool.pool_size if hasattr(smtp_pool, 'pool_size') else 0,
                "timeout_seconds": smtp_pool.timeout if hasattr(smtp_pool, 'timeout') else 0
            }
            
            # Update Prometheus metrics
            self.smtp_connections.set(active_connections)
            
            return result
            
        except Exception as e:
            logger.error(f"SMTP pool health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e)
            }
    
    def record_verification_metrics(self, status: str, provider: str, duration: float):
        """Record verification metrics"""
        try:
            self.verifications_total.labels(status=status, provider=provider).inc()
            self.verification_latency.observe(duration)
        except Exception as e:
            logger.error(f"Error recording verification metrics: {e}")
    
    def record_cache_hit(self):
        """Record cache hit"""
        self.cache_hits.inc()
    
    def record_cache_miss(self):
        """Record cache miss"""
        self.cache_misses.inc()
    
    def record_smtp_error(self, error_type: str):
        """Record SMTP error"""
        self.smtp_errors.labels(error_type=error_type).inc()

class AlertManager:
    """Handle system alerts and notifications"""
    
    def __init__(self):
        self.alert_thresholds = {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'disk_usage_percent': 90.0,
            'error_rate': 5.0,  # errors per minute
            'response_time': 5.0  # seconds
        }
        self.alert_history = []
    
    def check_system_alerts(self, metrics: SystemMetrics) -> List[Dict[str, Any]]:
        """Check for system-level alerts"""
        alerts = []
        
        # CPU usage alert
        if metrics.cpu_percent > self.alert_thresholds['cpu_percent']:
            alerts.append({
                "type": "high_cpu_usage",
                "severity": "warning",
                "message": f"CPU usage is {metrics.cpu_percent:.1f}% (threshold: {self.alert_thresholds['cpu_percent']}%)",
                "value": metrics.cpu_percent,
                "threshold": self.alert_thresholds['cpu_percent'],
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Memory usage alert
        if metrics.memory_percent > self.alert_thresholds['memory_percent']:
            alerts.append({
                "type": "high_memory_usage",
                "severity": "warning",
                "message": f"Memory usage is {metrics.memory_percent:.1f}% (threshold: {self.alert_thresholds['memory_percent']}%)",
                "value": metrics.memory_percent,
                "threshold": self.alert_thresholds['memory_percent'],
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Disk usage alert
        if metrics.disk_usage_percent > self.alert_thresholds['disk_usage_percent']:
            alerts.append({
                "type": "high_disk_usage",
                "severity": "critical",
                "message": f"Disk usage is {metrics.disk_usage_percent:.1f}% (threshold: {self.alert_thresholds['disk_usage_percent']}%)",
                "value": metrics.disk_usage_percent,
                "threshold": self.alert_thresholds['disk_usage_percent'],
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Log alerts
        for alert in alerts:
            logger.warning(f"ALERT: {alert['message']}")
            self.alert_history.append(alert)
        
        # Keep only recent alerts (last 24 hours)
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        self.alert_history = [
            alert for alert in self.alert_history 
            if datetime.fromisoformat(alert['timestamp']) > cutoff_time
        ]
        
        return alerts
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get alerts from the last N hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return [
            alert for alert in self.alert_history
            if datetime.fromisoformat(alert['timestamp']) > cutoff_time
        ]

class PerformanceProfiler:
    """Profile application performance"""
    
    def __init__(self):
        self.request_times = []
        self.slow_queries = []
        self.error_counts = {}
    
    def record_request_time(self, endpoint: str, duration: float):
        """Record request processing time"""
        self.request_times.append({
            "endpoint": endpoint,
            "duration": duration,
            "timestamp": datetime.utcnow()
        })
        
        # Keep only recent data (last hour)
        cutoff_time = datetime.utcnow() - timedelta(hours=1)
        self.request_times = [
            req for req in self.request_times
            if req['timestamp'] > cutoff_time
        ]
        
        # Log slow requests
        if duration > 5.0:  # 5 seconds threshold
            self.slow_queries.append({
                "endpoint": endpoint,
                "duration": duration,
                "timestamp": datetime.utcnow()
            })
            logger.warning(f"Slow request detected: {endpoint} took {duration:.2f}s")
    
    def record_error(self, error_type: str):
        """Record application errors"""
        if error_type not in self.error_counts:
            self.error_counts[error_type] = 0
        self.error_counts[error_type] += 1
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        if not self.request_times:
            return {
                "avg_response_time": 0.0,
                "max_response_time": 0.0,
                "min_response_time": 0.0,
                "total_requests": 0,
                "slow_requests": 0,
                "error_summary": self.error_counts
            }
        
        durations = [req['duration'] for req in self.request_times]
        
        return {
            "avg_response_time": sum(durations) / len(durations),
            "max_response_time": max(durations),
            "min_response_time": min(durations),
            "total_requests": len(durations),
            "slow_requests": len(self.slow_queries),
            "error_summary": self.error_counts
        }

# Global monitoring instances
health_monitor = HealthMonitor()
alert_manager = AlertManager()
performance_profiler = PerformanceProfiler() 