"""ShieldFlow — Cryptographic trust boundaries for AI agents."""

from shieldflow.core.context import SecureContext
from shieldflow.core.policy import PolicyEngine
from shieldflow.core.session import (
    DEFAULT_KEY_ROTATION_INTERVAL_SECONDS,
    DEFAULT_MAX_SESSION_DURATION_SECONDS,
    SecureSession,
    SessionExpiryError,
)
from shieldflow.core.trust import TrustLevel
from shieldflow.core.validator import ActionValidator
from shieldflow.exceptions import (
    ShieldFlowError,
    PolicyLoadError,
    ValidationError,
    TrustLevelError,
    ConfigurationError,
    RateLimitError,
    AnomalyError,
)
from shieldflow.shieldflow import ShieldFlow

__version__ = "0.2.0"

__all__ = [
    "ShieldFlow",
    "SecureContext",
    "SecureSession",
    "TrustLevel",
    "PolicyEngine",
    "ActionValidator",
    "SessionExpiryError",
    "DEFAULT_MAX_SESSION_DURATION_SECONDS",
    "DEFAULT_KEY_ROTATION_INTERVAL_SECONDS",
    # Exceptions
    "ShieldFlowError",
    "PolicyLoadError",
    "ValidationError",
    "TrustLevelError",
    "ConfigurationError",
    "RateLimitError",
    "AnomalyError",
]
