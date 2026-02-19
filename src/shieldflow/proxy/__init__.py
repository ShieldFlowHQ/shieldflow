"""ShieldFlow proxy server package.

The proxy sits between clients and upstream LLM providers, enforcing
trust boundaries on every request and response.

Usage::

    from shieldflow.proxy.config import ProxyConfig
    from shieldflow.proxy.server import create_app

    config = ProxyConfig.from_yaml("config.yaml")
    app = create_app(config)

    # Run with:  uvicorn shieldflow.proxy.server:app
"""

from shieldflow.proxy.anomaly import AnomalyMonitor
from shieldflow.proxy.audit import AuditLogger
from shieldflow.proxy.config import ProxyConfig, TenantConfig, UpstreamConfig
from shieldflow.proxy.dashboard import DecisionLog
from shieldflow.proxy.metrics import MetricsCollector
from shieldflow.proxy.ratelimit import RateLimiter
from shieldflow.proxy.server import create_app

__all__ = [
    "AnomalyMonitor",
    "AuditLogger",
    "DecisionLog",
    "MetricsCollector",
    "ProxyConfig",
    "RateLimiter",
    "TenantConfig",
    "UpstreamConfig",
    "create_app",
]
