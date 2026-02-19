"""In-process metrics collector for the ShieldFlow proxy.

Provides thread-safe counters exposed via two endpoints:

* ``GET /metrics``      — Prometheus text exposition format (v0.0.4)
* ``GET /metrics/json`` — JSON snapshot for programmatic consumers

No external dependencies are required; the Prometheus text format is
implemented directly to avoid adding a heavyweight client library.

Tracked metrics
---------------
``shieldflow_requests_total``
    Counter — total proxy requests received.

``shieldflow_decisions_total``
    Counter with labels ``decision``, ``tool``, ``trigger_trust`` — one
    increment per validated tool call.

``shieldflow_blocked_patterns_total``
    Counter with label ``pattern`` — incremented for each matched pattern
    name that caused a BLOCK (from ``ValidationResult.matched_patterns``).

``shieldflow_normalisation_flags_total``
    Counter with label ``flag`` — incremented for each sanitiser flag
    present on a BLOCK decision.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any


class MetricsCollector:
    """Thread-safe in-process metrics collector.

    All public methods are safe to call from concurrent async handlers.
    The underlying store uses a ``threading.Lock`` for correctness under
    both threaded and async workloads.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # (decision, tool_name, trigger_trust) → count
        self._decisions: dict[tuple[str, str, str], int] = defaultdict(int)
        self._patterns: dict[str, int] = defaultdict(int)
        self._norm_flags: dict[str, int] = defaultdict(int)
        self._requests_total: int = 0

    # ------------------------------------------------------------------ #
    # Recording                                                            #
    # ------------------------------------------------------------------ #

    def record_request(self) -> None:
        """Increment the ``requests_total`` counter."""
        with self._lock:
            self._requests_total += 1

    def record_decision(
        self,
        decision: str,
        tool_name: str,
        trigger_trust: str,
        matched_patterns: list[str] | None = None,
        normalisation_flags: list[str] | None = None,
    ) -> None:
        """Record a single tool-call validation decision.

        Args:
            decision: ``"BLOCK"``, ``"ALLOW"``, or ``"CONFIRM"``.
            tool_name: The tool/function that was validated.
            trigger_trust: Trust level name of the triggering source.
            matched_patterns: Pattern names from the blocked event
                (only populated for BLOCK decisions).
            normalisation_flags: Sanitiser flags from the blocked event
                (only populated for BLOCK decisions).
        """
        with self._lock:
            self._decisions[(decision, tool_name, trigger_trust)] += 1
            for p in (matched_patterns or []):
                self._patterns[p] += 1
            for f in (normalisation_flags or []):
                self._norm_flags[f] += 1

    # ------------------------------------------------------------------ #
    # Snapshots                                                            #
    # ------------------------------------------------------------------ #

    def snapshot(self) -> dict[str, Any]:
        """Return a point-in-time JSON-serialisable snapshot.

        Returns a dict with the following keys:

        ``requests_total``
            Total requests received since startup.
        ``decisions``
            Aggregate counts: ``block_total``, ``allow_total``,
            ``confirm_total``.
        ``decisions_by_tool``
            Nested mapping ``{tool_name: {decision: count}}``.
        ``top_blocked_patterns``
            Top-20 ``[pattern, count]`` pairs sorted by count desc.
        ``top_normalisation_flags``
            All ``[flag, count]`` pairs sorted by count desc.
        """
        with self._lock:
            decisions = dict(self._decisions)
            patterns = dict(self._patterns)
            norm_flags = dict(self._norm_flags)
            requests_total = self._requests_total

        block_total = sum(
            v for (d, _, _), v in decisions.items() if d == "BLOCK"
        )
        allow_total = sum(
            v for (d, _, _), v in decisions.items() if d == "ALLOW"
        )
        confirm_total = sum(
            v for (d, _, _), v in decisions.items() if d == "CONFIRM"
        )

        by_tool: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for (decision, tool, _), count in decisions.items():
            by_tool[tool][decision] += count

        return {
            "requests_total": requests_total,
            "decisions": {
                "block_total": block_total,
                "allow_total": allow_total,
                "confirm_total": confirm_total,
            },
            "decisions_by_tool": {
                tool: dict(counts) for tool, counts in by_tool.items()
            },
            "top_blocked_patterns": sorted(
                patterns.items(), key=lambda x: x[1], reverse=True
            )[:20],
            "top_normalisation_flags": sorted(
                norm_flags.items(), key=lambda x: x[1], reverse=True
            ),
        }

    def prometheus_text(self) -> str:
        """Render all metrics in Prometheus text exposition format.

        Compatible with Prometheus, VictoriaMetrics, and any
        OpenMetrics-compatible scraper.

        Returns:
            String in Prometheus text format
            (Content-Type: ``text/plain; version=0.0.4``).
        """
        with self._lock:
            decisions = dict(self._decisions)
            patterns = dict(self._patterns)
            norm_flags = dict(self._norm_flags)
            requests_total = self._requests_total

        lines: list[str] = []

        # ── shieldflow_requests_total ──────────────────────────────────
        lines += [
            "# HELP shieldflow_requests_total"
            " Total proxy requests received.",
            "# TYPE shieldflow_requests_total counter",
            f"shieldflow_requests_total {requests_total}",
            "",
        ]

        # ── shieldflow_decisions_total ─────────────────────────────────
        lines += [
            "# HELP shieldflow_decisions_total"
            " Tool-call validation decisions by type, tool, and trust.",
            "# TYPE shieldflow_decisions_total counter",
        ]
        for (decision, tool, trust), count in sorted(decisions.items()):
            lbl = (
                f'decision="{decision}",'
                f'tool="{tool}",'
                f'trigger_trust="{trust}"'
            )
            lines.append(f"shieldflow_decisions_total{{{lbl}}} {count}")
        lines.append("")

        # ── shieldflow_blocked_patterns_total ─────────────────────────
        lines += [
            "# HELP shieldflow_blocked_patterns_total"
            " Injection patterns that triggered BLOCK decisions.",
            "# TYPE shieldflow_blocked_patterns_total counter",
        ]
        for pattern, count in sorted(patterns.items()):
            lbl = f'pattern="{_escape_label(pattern)}"'
            lines.append(
                f"shieldflow_blocked_patterns_total{{{lbl}}} {count}"
            )
        lines.append("")

        # ── shieldflow_normalisation_flags_total ───────────────────────
        lines += [
            "# HELP shieldflow_normalisation_flags_total"
            " Sanitiser normalisation flags raised during content scanning.",
            "# TYPE shieldflow_normalisation_flags_total counter",
        ]
        for flag, count in sorted(norm_flags.items()):
            lbl = f'flag="{_escape_label(flag)}"'
            lines.append(
                f"shieldflow_normalisation_flags_total{{{lbl}}} {count}"
            )
        lines.append("")

        return "\n".join(lines)


def _escape_label(value: str) -> str:
    r"""Escape a Prometheus label value per the text format spec.

    Replaces ``\`` → ``\\``, ``"`` → ``\"``, newline → ``\n``.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
