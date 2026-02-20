"""Per-key sliding-window rate limiter for the ShieldFlow proxy.

Limits are expressed in *requests per minute* (RPM).  The implementation
uses a deque-based sliding window: each key tracks the timestamps of its
recent requests, and any timestamp older than 60 s is discarded before
each check.

Thread-safety
-------------
All public methods acquire a single ``threading.Lock``.  The limiter is
safe to call from concurrent async handlers operating over a shared event
loop with thread-pool executor tasks.

Usage::

    limiter = RateLimiter(rpm=60)

    # In a request handler:
    limiter.check("api-key-abc")   # raises HTTP 429 if over limit
    # ... handle request ...

    # Or as a boolean check:
    if not limiter.is_allowed("api-key-abc"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

Disabling
---------
Set ``rpm=0`` (the default) to disable rate limiting entirely.
:func:`check` and :func:`is_allowed` become no-ops in that case.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException

# ─── Constants ────────────────────────────────────────────────────────────────

_WINDOW_SECONDS: float = 60.0
"""Sliding window duration in seconds."""


# ─── Rate limiter ─────────────────────────────────────────────────────────────


class RateLimiter:
    """Sliding-window rate limiter keyed by an arbitrary string.

    Args:
        rpm: Maximum requests allowed per key per 60-second window.
            Set to ``0`` to disable rate limiting.
    """

    def __init__(self, rpm: int = 0) -> None:
        self._rpm = rpm
        self._windows: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    @property
    def rpm(self) -> int:
        """Configured requests-per-minute limit (0 = disabled)."""
        return self._rpm

    def is_allowed(self, key: str) -> bool:
        """Return ``True`` if *key* is within its rate limit.

        Calling this method **does not** consume a rate-limit slot.
        Use :meth:`check` to both verify and record the request.

        Args:
            key: Opaque rate-limit key (e.g. API key or IP address).
        """
        if self._rpm == 0:
            return True
        with self._lock:
            self._evict_locked(key)
            dq = self._windows.get(key)
            return (dq is not None and len(dq) < self._rpm) or (dq is None)

    def check(self, key: str) -> None:
        """Record a request for *key* and raise HTTP 429 if over limit.

        Args:
            key: Opaque rate-limit key (e.g. API key or IP address).

        Raises:
            :class:`fastapi.HTTPException` (429) if the key has exceeded
            its ``rpm`` quota in the current 60-second window.
        """
        if self._rpm == 0:
            return
        with self._lock:
            self._evict_locked(key)
            dq = self._windows.get(key)
            if dq is None:
                dq = deque()
                self._windows[key] = dq
            if len(dq) >= self._rpm:
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"Rate limit exceeded: {self._rpm} requests per minute allowed. "
                        "Please retry after a short delay."
                    ),
                )
            dq.append(time.monotonic())

    def current_count(self, key: str) -> int:
        """Number of requests from *key* in the current 60-second window.

        Useful for testing and monitoring without consuming a slot.
        """
        if self._rpm == 0:
            return 0
        with self._lock:
            self._evict_locked(key)
            dq = self._windows.get(key)
            return len(dq) if dq else 0

    def remaining(self, key: str) -> int:
        """Number of requests remaining for *key* in the current window.

        Returns 0 if over limit, otherwise returns (rpm - current_count).
        """
        if self._rpm == 0:
            return 0  # Unlimited, but we return 0 for consistency
        with self._lock:
            self._evict_locked(key)
            dq = self._windows.get(key)
            count = len(dq) if dq else 0
            return max(0, self._rpm - count)

    def reset_time(self, key: str) -> int:
        """Unix timestamp when the rate limit window will reset for *key*.

        Returns 0 if rate limiting is disabled or the key has no requests.
        """
        if self._rpm == 0:
            return 0
        with self._lock:
            self._evict_locked(key)
            dq = self._windows.get(key)
            if not dq:
                return 0
            # Window resets when the oldest request expires (60s from that request)
            oldest = dq[0] if dq else 0
            return int(oldest + _WINDOW_SECONDS)

    def reset(self, key: str) -> None:
        """Clear all recorded requests for *key* (testing / admin use)."""
        with self._lock:
            self._windows.pop(key, None)

    def active_keys(self) -> list[str]:
        """Keys with at least one request in the current window."""
        with self._lock:
            now = time.monotonic()
            cutoff = now - _WINDOW_SECONDS
            return [
                k for k, dq in self._windows.items()
                if dq and dq[-1] >= cutoff
            ]

    def cleanup(self, max_age_seconds: int = 300) -> int:
        """Remove entries older than max_age_seconds. Returns count removed."""
        removed = 0
        now = time.monotonic()
        with self._lock:
            for key in list(self._windows.keys()):
                dq = self._windows.get(key)
                if dq:
                    # Remove old entries
                    while dq and now - dq[0] > max_age_seconds:
                        dq.popleft()
                        removed += 1
                    if not dq:
                        del self._windows[key]
        return removed

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _evict_locked(self, key: str) -> None:
        """Remove timestamps outside the sliding window (lock must be held)."""
        cutoff = time.monotonic() - _WINDOW_SECONDS
        
        # Clean up the specified key
        dq = self._windows.get(key)
        if dq is not None:
            while dq and dq[0] < cutoff:
                dq.popleft()
            # Remove empty deques to prevent unbounded dict growth
            if not dq:
                self._windows.pop(key, None)
        
        # Also clean up any other empty deques to prevent memory leaks
        # This is a simple lazy cleanup strategy
        keys_to_remove = [
            k for k, d in self._windows.items() 
            if not d
        ]
        for k in keys_to_remove:
            self._windows.pop(k, None)
