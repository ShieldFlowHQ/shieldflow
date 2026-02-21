"""Structured logging for ShieldFlow.

Provides JSON-structured logging with automatic context injection.
"""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ("msg", "args", "exc_info", "exc_text", "levelname", 
                          "levelno", "pathname", "filename", "module", "lineno",
                          "funcName", "created", "msecs", "relativeCreated",
                          "thread", "threadName", "processName", "process",
                          "message", "name", "stack_info"):
                log_obj[key] = value
        
        return json.dumps(log_obj)


def get_logger(name: str, context: dict[str, Any] | None = None) -> logging.Logger:
    """Get a structured logger with optional context.
    
    Args:
        name: Logger name (typically __name__)
        context: Optional static context to include in all logs
    
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    
    if context:
        # Store context for use in log calls
        logger._context = context
    
    return logger


def log_with_context(logger: logging.Logger, level: int, message: str, 
                     **kwargs: Any) -> None:
    """Log a message with additional context.
    
    Args:
        logger: Logger instance
        level: Log level (logging.INFO, etc.)
        message: Log message
        **kwargs: Additional context fields
    """
    extra = getattr(logger, "_context", {}) or {}
    extra.update(kwargs)
    
    # Create a new record with extra context
    # Using a simple approach: pass as 'extra' to log
    logger.log(level, message, extra=extra)


# Convenience functions
def info(logger: logging.Logger, message: str, **kwargs: Any) -> None:
    """Log info with context."""
    log_with_context(logger, logging.INFO, message, **kwargs)


def warning(logger: logging.Logger, message: str, **kwargs: Any) -> None:
    """Log warning with context."""
    log_with_context(logger, logging.WARNING, message, **kwargs)


def error(logger: logging.Logger, message: str, **kwargs: Any) -> None:
    """Log error with context."""
    log_with_context(logger, logging.ERROR, message, **kwargs)


def debug(logger: logging.Logger, message: str, **kwargs: Any) -> None:
    """Log debug with context."""
    log_with_context(logger, logging.DEBUG, message, **kwargs)
