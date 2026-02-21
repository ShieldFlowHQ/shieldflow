"""ShieldFlow exception types."""

from __future__ import annotations


class ShieldFlowError(Exception):
    """Base exception for all ShieldFlow errors."""
    
    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or "UNKNOWN"


class PolicyLoadError(ShieldFlowError):
    """Failed to load or parse policy configuration."""
    
    def __init__(self, message: str) -> None:
        super().__init__(message, code="POLICY_LOAD_ERROR")


class ValidationError(ShieldFlowError):
    """Validation failed (e.g., invalid request, malformed data)."""
    
    def __init__(self, message: str) -> None:
        super().__init__(message, code="VALIDATION_ERROR")


class TrustLevelError(ShieldFlowError):
    """Trust level configuration or evaluation error."""
    
    def __init__(self, message: str) -> None:
        super().__init__(message, code="TRUST_LEVEL_ERROR")


class ConfigurationError(ShieldFlowError):
    """Configuration error (missing config, invalid values)."""
    
    def __init__(self, message: str) -> None:
        super().__init__(message, code="CONFIG_ERROR")


class RateLimitError(ShieldFlowError):
    """Rate limit exceeded."""
    
    def __init__(self, message: str, retry_after: int | None = None) -> None:
        super().__init__(message, code="RATE_LIMIT_ERROR")
        self.retry_after = retry_after


class AnomalyError(ShieldFlowError):
    """Anomaly detection error."""
    
    def __init__(self, message: str) -> None:
        super().__init__(message, code="ANOMALY_ERROR")
