"""Session-level anomaly detection for the ShieldFlow proxy.

Tracks per-session decision sequences across multiple requests and emits
risk signals when a session's block rate spikes — indicating a likely
prompt-injection attack in progress.

Design
------
* **Session identity** — callers pass an optional ``X-ShieldFlow-Session-ID``
  header.  If omitted, anomaly tracking is skipped for that request (the
  proxy is stateless by default).  The session ID is caller-supplied and
  opaque; ShieldFlow does not verify it.

* **Risk score** — a rolling weighted average over the last
  ``WINDOW_SIZE`` decisions, where:

  - ``BLOCK``   → weight 1.0  (high-risk event)
  - ``CONFIRM`` → weight 0.3  (elevated-risk event; human review needed)
  - ``ALLOW``   → weight 0.0  (nominal)

  Score range: 0.0 (all ALLOW) → 1.0 (all BLOCK).

* **Spike detection** — a session is *anomalous* when:

  1. Its risk score exceeds ``SPIKE_THRESHOLD`` (default 0.5), **and**
  2. The window contains at least ``MIN_DECISIONS`` decisions (avoids
     false positives on cold sessions), **and**
  3. The last untrusted-source decision was BLOCK (recent active attack).

* **Memory bound** — at most ``MAX_SESSIONS`` sessions are tracked.
  When the cap is reached, the session with the oldest last-seen
  timestamp is evicted.  Session state expires after ``TTL_SECONDS``
  of inactivity.

Prometheus metrics emitted
--------------------------
``shieldflow_session_risk_score{session_id}``
    Gauge — current risk score (0.0–1.0) for each active session.

``shieldflow_anomaly_spikes_total``
    Counter — total number of spike events detected (any session).

``shieldflow_active_sessions``
    Gauge — number of sessions currently tracked.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

# ─── Configuration constants ──────────────────────────────────────────────────

# Default values — can be overridden via config or environment variables
_DEFAULT_WINDOW_SIZE: int = 20
"""Default number of recent decisions to include in the rolling risk score."""

_DEFAULT_SPIKE_THRESHOLD: float = 0.5
"""Default risk score above which a session is considered anomalous."""

_DEFAULT_MIN_DECISIONS: int = 3
"""Default minimum decisions in the window before spike detection activates."""


def _get_configurable_int(name: str, default: int, env_prefix: str = "SHIELDFLOW_ANOMALY_") -> int:
    """Load an integer config value from environment or use default."""
    import os
    env_key = f"{env_prefix}{name}"
    val = os.environ.get(env_key)
    if val is not None:
        try:
            return int(val)
        except ValueError:
            pass
    return default


def _get_configurable_float(name: str, default: float, env_prefix: str = "SHIELDFLOW_ANOMALY_") -> float:
    """Load a float config value from environment or use default."""
    import os
    env_key = f"{env_prefix}{name}"
    val = os.environ.get(env_key)
    if val is not None:
        try:
            return float(val)
        except ValueError:
            pass
    return default


# Module-level defaults that can be read at runtime
WINDOW_SIZE: int = _get_configurable_int("WINDOW_SIZE", _DEFAULT_WINDOW_SIZE)
"""Number of recent decisions to include in the rolling risk score."""

SPIKE_THRESHOLD: float = _get_configurable_float("SPIKE_THRESHOLD", _DEFAULT_SPIKE_THRESHOLD)
"""Risk score above which a session is considered anomalous."""

MIN_DECISIONS: int = _get_configurable_int("MIN_DECISIONS", _DEFAULT_MIN_DECISIONS)
"""Minimum decisions in the window before spike detection activates."""

MAX_SESSIONS: int = 1_000
"""Maximum number of active sessions tracked simultaneously."""

TTL_SECONDS: int = 3_600
"""Seconds of inactivity before a session's state is evicted."""

_DECISION_WEIGHTS: dict[str, float] = {
    "BLOCK": 1.0,
    "CONFIRM": 0.3,
    "ALLOW": 0.0,
}


# ─── Data model ───────────────────────────────────────────────────────────────


@dataclass
class DecisionPoint:
    """A single recorded decision within a session window."""

    ts: float
    decision: str  # "BLOCK" | "ALLOW" | "CONFIRM"
    trigger_trust: str  # TrustLevel.name, e.g. "NONE", "OWNER"
    tool_name: str


@dataclass
class SessionState:
    """Rolling decision window + derived signals for one session."""

    session_id: str
    window: deque[DecisionPoint] = field(default_factory=lambda: deque(maxlen=WINDOW_SIZE))
    spike_count: int = 0
    last_seen: float = field(default_factory=time.monotonic)
    window_size: int = WINDOW_SIZE
    spike_threshold: float = SPIKE_THRESHOLD
    min_decisions: int = MIN_DECISIONS

    # ------------------------------------------------------------------ #
    # Derived properties                                                   #
    # ------------------------------------------------------------------ #

    def record(self, decision: str, trigger_trust: str, tool_name: str) -> None:
        """Append a new decision point to the rolling window."""
        self.last_seen = time.monotonic()
        self.window.append(
            DecisionPoint(
                ts=self.last_seen,
                decision=decision.upper(),
                trigger_trust=trigger_trust,
                tool_name=tool_name,
            )
        )

    def risk_score(self) -> float:
        """Weighted mean of decisions in the current window.

        Returns 0.0 if the window is empty.
        """
        if not self.window:
            return 0.0
        total = sum(_DECISION_WEIGHTS.get(p.decision, 0.0) for p in self.window)
        return total / len(self.window)

    def is_anomalous(self) -> bool:
        """True when spike conditions are met (see module docstring)."""
        if len(self.window) < self.min_decisions:
            return False
        if self.risk_score() < self.spike_threshold:
            return False
        # Condition 3: the most recent decision from an untrusted source is BLOCK
        for point in reversed(self.window):
            if point.trigger_trust in ("NONE", "USER"):
                return point.decision == "BLOCK"
        return False

    def summary(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary of this session's state."""
        counts: dict[str, int] = {"BLOCK": 0, "ALLOW": 0, "CONFIRM": 0}
        for p in self.window:
            counts[p.decision] = counts.get(p.decision, 0) + 1
        return {
            "session_id": self.session_id,
            "risk_score": round(self.risk_score(), 3),
            "anomalous": self.is_anomalous(),
            "window_size": len(self.window),
            "spike_count": self.spike_count,
            "decisions": counts,
            "last_seen": self.last_seen,
        }


# ─── Monitor ──────────────────────────────────────────────────────────────────


class AnomalyMonitor:
    """Thread-safe multi-session anomaly detector.

    Typical usage::

        monitor = AnomalyMonitor()

        # On each validated tool call:
        monitor.record(
            session_id="sess-abc",
            decision="BLOCK",
            trigger_trust="NONE",
            tool_name="exec",
        )

        score = monitor.risk_score("sess-abc")         # 0.0–1.0
        at_risk = monitor.is_anomalous("sess-abc")     # True / False
    """

    def __init__(
        self,
        max_sessions: int = MAX_SESSIONS,
        ttl_seconds: int = TTL_SECONDS,
        window_size: int = WINDOW_SIZE,
        spike_threshold: float = SPIKE_THRESHOLD,
        min_decisions: int = MIN_DECISIONS,
    ) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionState] = {}
        self._max_sessions = max_sessions
        self._ttl_seconds = ttl_seconds
        self._window_size = window_size
        self._spike_threshold = spike_threshold
        self._min_decisions = min_decisions
        self._total_spikes: int = 0

    # ------------------------------------------------------------------ #
    # Recording                                                            #
    # ------------------------------------------------------------------ #

    def record(
        self,
        session_id: str,
        decision: str,
        trigger_trust: str,
        tool_name: str = "unknown",
    ) -> None:
        """Record a validated tool-call decision for the given session.

        Args:
            session_id: Caller-supplied opaque session identifier.
            decision: ``"BLOCK"``, ``"ALLOW"``, or ``"CONFIRM"``.
            trigger_trust: TrustLevel name of the trigger source.
            tool_name: Name of the tool that was validated.
        """
        with self._lock:
            self._evict_stale_locked()
            state = self._get_or_create_locked(session_id)
            was_anomalous = state.is_anomalous()
            state.record(decision, trigger_trust, tool_name)
            if state.is_anomalous() and not was_anomalous:
                # Rising edge — new spike
                state.spike_count += 1
                self._total_spikes += 1

    # ------------------------------------------------------------------ #
    # Queries                                                              #
    # ------------------------------------------------------------------ #

    def risk_score(self, session_id: str) -> float:
        """Current risk score for *session_id*.  Returns 0.0 if unknown."""
        with self._lock:
            state = self._sessions.get(session_id)
            return state.risk_score() if state else 0.0

    def is_anomalous(self, session_id: str) -> bool:
        """True if *session_id* is currently above the spike threshold."""
        with self._lock:
            state = self._sessions.get(session_id)
            return state.is_anomalous() if state else False

    def session_summary(self, session_id: str) -> dict[str, Any] | None:
        """JSON-serialisable summary dict, or *None* if session unknown."""
        with self._lock:
            state = self._sessions.get(session_id)
            return state.summary() if state else None

    def sessions_at_risk(self) -> list[str]:
        """Return session IDs whose risk score currently exceeds the threshold."""
        with self._lock:
            return [sid for sid, s in self._sessions.items() if s.is_anomalous()]

    def active_session_count(self) -> int:
        """Number of sessions currently tracked."""
        with self._lock:
            return len(self._sessions)

    def total_spikes(self) -> int:
        """Total spike-rising-edge events observed since startup."""
        with self._lock:
            return self._total_spikes

    # ------------------------------------------------------------------ #
    # Prometheus exposition                                                #
    # ------------------------------------------------------------------ #

    def prometheus_text(self) -> str:
        """Emit Prometheus text-format metrics for all active sessions.

        Included metrics:

        * ``shieldflow_session_risk_score{session_id}`` — gauge
        * ``shieldflow_anomaly_spikes_total`` — counter
        * ``shieldflow_active_sessions`` — gauge
        """
        with self._lock:
            lines: list[str] = []

            # Risk score per session
            lines.append(
                "# HELP shieldflow_session_risk_score Rolling risk score (0–1) per session"
            )
            lines.append("# TYPE shieldflow_session_risk_score gauge")
            for sid, state in self._sessions.items():
                safe_sid = sid.replace('"', '\\"')
                lines.append(
                    f'shieldflow_session_risk_score{{session_id="{safe_sid}"}} '
                    f"{state.risk_score():.4f}"
                )

            # Global spike counter
            lines.append(
                "# HELP shieldflow_anomaly_spikes_total "
                "Total anomaly spike rising-edge events observed"
            )
            lines.append("# TYPE shieldflow_anomaly_spikes_total counter")
            lines.append(f"shieldflow_anomaly_spikes_total {self._total_spikes}")

            # Active session gauge
            lines.append(
                "# HELP shieldflow_active_sessions Number of sessions currently tracked"
            )
            lines.append("# TYPE shieldflow_active_sessions gauge")
            lines.append(f"shieldflow_active_sessions {len(self._sessions)}")

            return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _get_or_create_locked(self, session_id: str) -> SessionState:
        """Return existing state or create new (lock must be held)."""
        if session_id not in self._sessions:
            if len(self._sessions) >= self._max_sessions:
                self._evict_oldest_locked()
            self._sessions[session_id] = SessionState(
                session_id=session_id,
                window_size=self._window_size,
                spike_threshold=self._spike_threshold,
                min_decisions=self._min_decisions,
            )
        return self._sessions[session_id]

    def _evict_stale_locked(self) -> None:
        """Remove sessions that have exceeded TTL (lock must be held)."""
        now = time.monotonic()
        cutoff = now - self._ttl_seconds
        stale = [sid for sid, s in self._sessions.items() if s.last_seen < cutoff]
        for sid in stale:
            del self._sessions[sid]

    def _evict_oldest_locked(self) -> None:
        """Remove the least-recently-seen session (lock must be held)."""
        if not self._sessions:
            return
        oldest = min(self._sessions, key=lambda sid: self._sessions[sid].last_seen)
        del self._sessions[oldest]
