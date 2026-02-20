"""Unit tests for the RateLimiter sliding-window rate limiter.

Covers:
- Disabled mode (rpm=0)
- Counting within and across the sliding window
- check() raises HTTP 429 when limit exceeded
- is_allowed() query without consuming a slot
- current_count() accuracy
- reset() clears state
- active_keys() listing
- Thread-safety smoke test
- Window expiry (time-based eviction)
"""

from __future__ import annotations

import threading

import pytest

from shieldflow.proxy.ratelimit import _WINDOW_SECONDS, RateLimiter

# ─── Disabled mode ─────────────────────────────────────────────────────────────


class TestDisabledMode:
    def test_rpm_zero_is_always_allowed(self) -> None:
        rl = RateLimiter(rpm=0)
        assert rl.is_allowed("any-key")

    def test_rpm_zero_check_never_raises(self) -> None:
        rl = RateLimiter(rpm=0)
        for _ in range(1_000):
            rl.check("any-key")  # must not raise

    def test_rpm_zero_current_count_is_zero(self) -> None:
        rl = RateLimiter(rpm=0)
        rl.check("key")
        assert rl.current_count("key") == 0

    def test_rpm_property(self) -> None:
        assert RateLimiter(rpm=0).rpm == 0
        assert RateLimiter(rpm=60).rpm == 60


# ─── Normal operation ──────────────────────────────────────────────────────────


class TestNormalOperation:
    def test_first_request_allowed(self) -> None:
        rl = RateLimiter(rpm=5)
        assert rl.is_allowed("key")

    def test_check_within_limit_does_not_raise(self) -> None:
        rl = RateLimiter(rpm=5)
        for _ in range(5):
            rl.check("key")  # should not raise

    def test_check_exceeding_limit_raises_429(self) -> None:
        from fastapi import HTTPException

        rl = RateLimiter(rpm=3)
        for _ in range(3):
            rl.check("key")
        with pytest.raises(HTTPException) as exc_info:
            rl.check("key")
        assert exc_info.value.status_code == 429

    def test_is_allowed_false_at_limit(self) -> None:
        rl = RateLimiter(rpm=2)
        rl.check("key")
        rl.check("key")
        assert not rl.is_allowed("key")

    def test_is_allowed_does_not_consume_slot(self) -> None:
        rl = RateLimiter(rpm=2)
        for _ in range(10):
            rl.is_allowed("key")
        # Should still be at 0 consumed
        assert rl.current_count("key") == 0

    def test_current_count_tracks_checks(self) -> None:
        rl = RateLimiter(rpm=10)
        assert rl.current_count("key") == 0
        rl.check("key")
        assert rl.current_count("key") == 1
        rl.check("key")
        assert rl.current_count("key") == 2

    def test_different_keys_are_independent(self) -> None:
        """Each key's limit is tracked independently."""
        from fastapi import HTTPException

        rl = RateLimiter(rpm=1)
        # First request for each key succeeds — keys don't share a bucket
        rl.check("key-a")
        rl.check("key-b")
        # Both keys are now at their limit
        with pytest.raises(HTTPException):
            rl.check("key-a")
        with pytest.raises(HTTPException):
            rl.check("key-b")

    def test_keys_isolated_from_each_other(self) -> None:
        rl = RateLimiter(rpm=3)
        for _ in range(3):
            rl.check("alice")
        # alice is at limit; bob is fine
        assert not rl.is_allowed("alice")
        assert rl.is_allowed("bob")

    def test_reset_clears_key(self) -> None:
        from fastapi import HTTPException

        rl = RateLimiter(rpm=2)
        rl.check("key")
        rl.check("key")
        with pytest.raises(HTTPException):
            rl.check("key")
        rl.reset("key")
        rl.check("key")  # should succeed after reset

    def test_reset_unknown_key_is_noop(self) -> None:
        rl = RateLimiter(rpm=5)
        rl.reset("ghost")  # must not raise

    def test_active_keys_empty_initially(self) -> None:
        rl = RateLimiter(rpm=5)
        assert rl.active_keys() == []

    def test_active_keys_lists_checked_keys(self) -> None:
        rl = RateLimiter(rpm=5)
        rl.check("alice")
        rl.check("bob")
        keys = rl.active_keys()
        assert "alice" in keys
        assert "bob" in keys

    def test_active_keys_excludes_reset_keys(self) -> None:
        rl = RateLimiter(rpm=5)
        rl.check("alice")
        rl.reset("alice")
        assert "alice" not in rl.active_keys()


# ─── Window expiry ─────────────────────────────────────────────────────────────


class TestWindowExpiry:
    def test_expired_requests_not_counted(self) -> None:
        """After the window expires, old requests don't count toward the limit."""
        rl = RateLimiter(rpm=2)
        # Manually inject an old timestamp by manipulating the internal deque
        # (equivalent to requests that happened more than 60s ago)
        import time as _time

        with rl._lock:
            rl._windows["key"].append(_time.monotonic() - _WINDOW_SECONDS - 1)
            rl._windows["key"].append(_time.monotonic() - _WINDOW_SECONDS - 1)
        # Both slots are expired; 2 new requests should succeed
        rl.check("key")
        rl.check("key")
        assert rl.current_count("key") == 2

    def test_partial_window_eviction(self) -> None:
        """Only timestamps outside the window are evicted; recent ones remain."""
        import time as _time

        rl = RateLimiter(rpm=5)
        with rl._lock:
            # Add 3 old + 1 recent
            rl._windows["key"].append(_time.monotonic() - _WINDOW_SECONDS - 5)
            rl._windows["key"].append(_time.monotonic() - _WINDOW_SECONDS - 4)
            rl._windows["key"].append(_time.monotonic() - _WINDOW_SECONDS - 3)
            rl._windows["key"].append(_time.monotonic() - 1)  # still in window
        # After eviction (triggered by current_count), only 1 remains
        assert rl.current_count("key") == 1


# ─── Thread safety ─────────────────────────────────────────────────────────────


class TestThreadSafety:
    def test_concurrent_checks_no_data_race(self) -> None:
        """Multiple threads checking simultaneously should not corrupt state."""
        rl = RateLimiter(rpm=500)
        errors: list[Exception] = []

        def worker() -> None:
            try:
                for _ in range(10):
                    rl.check("shared-key")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Some HTTPExceptions (429s) are expected when over limit but not errors
        non_http = [
            e for e in errors
            if not (hasattr(e, "status_code") and e.status_code == 429)  # type: ignore[attr-defined]
        ]
        assert not non_http, f"Non-HTTP errors: {non_http}"

    def test_per_key_limit_concurrent(self) -> None:
        """Each key's limit is independently enforced under concurrency."""
        rpm = 10
        rl = RateLimiter(rpm=rpm)
        successes: dict[str, int] = {}
        lock = threading.Lock()

        def worker(key: str) -> None:
            count = 0
            for _ in range(rpm + 5):
                try:
                    rl.check(key)
                    count += 1
                except Exception:
                    pass
            with lock:
                successes[key] = count

        threads = [threading.Thread(target=worker, args=(f"key-{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for key, count in successes.items():
            assert count == rpm, (
                f"{key}: expected exactly {rpm} successes, got {count}"
            )
