"""Minimal security dashboard for ShieldFlow proxy decision triage.

Provides a self-contained HTML dashboard served directly by the proxy,
giving operators visibility into recent validation decisions without
needing an external observability stack.

Endpoints
---------
``GET /dashboard``
    HTML decision triage dashboard.  Filter by decision type, tool name,
    or trigger trust via query parameters::

        /dashboard?decision=BLOCK&tool=exec&trust=NONE

``GET /dashboard/api/decisions``
    JSON list of recent decisions (filterable).

``GET /dashboard/api/queue``
    JSON list of CONFIRM-pending decisions.

Acceptance criteria (Issue #8)
-------------------------------
* Operators can inspect *why* a request was blocked — each row includes
  an expandable provenance panel (matched patterns, normalisation flags,
  reason text).
* Confirmation-required actions are shown in a dedicated queue section
  at the top of the dashboard.
* UX supports filtering by source / action / trust level via the filter
  form (GET parameters, no JavaScript required).
"""

from __future__ import annotations

import html as _html
import json
import os
import sqlite3
import threading
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse

# ─── Data model ───────────────────────────────────────────────────────────────


@dataclass
class DecisionEntry:
    """A single recorded validation decision for the dashboard.

    Attributes:
        entry_id: Short unique ID for this entry (12 hex chars).
        timestamp: UTC ISO-8601 timestamp.
        request_id: UUID correlating all events for one proxy request.
        tool_name: The tool/function that was validated.
        decision: ``"BLOCK"``, ``"ALLOW"``, or ``"CONFIRM"``.
        reason: Human-readable explanation of the decision.
        trigger_source: Source identifier (e.g. ``"email"``).
        trigger_trust: Trust level of the triggering source.
        matched_patterns: Pattern keys that fired (BLOCK only).
        normalisation_flags: Sanitiser flags (BLOCK only).
        data_classification: Data classification label when applicable.
    """

    entry_id: str
    timestamp: str
    request_id: str
    tool_name: str
    decision: str
    reason: str
    trigger_source: str | None
    trigger_trust: str
    matched_patterns: list[str]
    normalisation_flags: list[str]
    data_classification: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "decision": self.decision,
            "reason": self.reason,
            "trigger_source": self.trigger_source,
            "trigger_trust": self.trigger_trust,
            "matched_patterns": self.matched_patterns,
            "normalisation_flags": self.normalisation_flags,
            "data_classification": self.data_classification,
        }


# ─── Ring-buffer log ──────────────────────────────────────────────────────────


class DecisionLog:
    """Thread-safe in-memory ring buffer of recent validation decisions.

    Stores up to *maxlen* entries (default 200).  Oldest entries are
    silently dropped when the buffer is full.
    
    Optionally persists to SQLite for survival across restarts.
    """

    def __init__(self, maxlen: int = 200, persist_path: str | None = None) -> None:
        self._lock = threading.Lock()
        self._entries: deque[DecisionEntry] = deque(maxlen=maxlen)
        self._persist_path = persist_path
        if persist_path:
            self._init_db()
            self._load_recent(maxlen)

    def _init_db(self) -> None:
        """Initialize SQLite database for persistence."""
        conn = sqlite3.connect(self._persist_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                request_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                trigger_source TEXT,
                trigger_trust TEXT NOT NULL,
                matched_patterns TEXT NOT NULL,
                normalisation_flags TEXT NOT NULL,
                data_classification TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON decisions(timestamp DESC)")
        conn.close()

    def _load_recent(self, maxlen: int) -> None:
        """Load recent decisions from SQLite."""
        if not self._persist_path:
            return
        try:
            conn = sqlite3.connect(self._persist_path)
            cursor = conn.execute(
                "SELECT * FROM decisions ORDER BY timestamp DESC LIMIT ?",
                (maxlen,)
            )
            rows = cursor.fetchall()
            conn.close()
            with self._lock:
                for row in reversed(rows):
                    entry = DecisionEntry(
                        entry_id=row[1],
                        timestamp=row[2],
                        request_id=row[3],
                        tool_name=row[4],
                        decision=row[5],
                        reason=row[6],
                        trigger_source=row[7],
                        trigger_trust=row[8],
                        matched_patterns=json.loads(row[9]),
                        normalisation_flags=json.loads(row[10]),
                        data_classification=row[11],
                    )
                    self._entries.append(entry)
        except Exception:
            pass  # Start fresh if persistence fails

    def _persist(self, entry: DecisionEntry) -> None:
        """Save a single decision to SQLite."""
        if not self._persist_path:
            return
        try:
            conn = sqlite3.connect(self._persist_path)
            conn.execute(
                """INSERT INTO decisions 
                   (entry_id, timestamp, request_id, tool_name, decision, reason,
                    trigger_source, trigger_trust, matched_patterns, normalisation_flags, data_classification)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry.entry_id,
                    entry.timestamp,
                    entry.request_id,
                    entry.tool_name,
                    entry.decision,
                    entry.reason,
                    entry.trigger_source,
                    entry.trigger_trust,
                    json.dumps(entry.matched_patterns),
                    json.dumps(entry.normalisation_flags),
                    entry.data_classification,
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass  # Non-fatal if persistence fails

    def record(
        self,
        request_id: str,
        tool_name: str,
        decision: str,
        reason: str,
        trigger_source: str | None = None,
        trigger_trust: str = "NONE",
        matched_patterns: list[str] | None = None,
        normalisation_flags: list[str] | None = None,
        data_classification: str | None = None,
    ) -> None:
        """Record a validation decision.

        Args:
            request_id: UUID for the originating proxy request.
            tool_name: Name of the validated tool/function.
            decision: ``"BLOCK"``, ``"ALLOW"``, or ``"CONFIRM"``.
            reason: Human-readable decision explanation.
            trigger_source: Source identifier (e.g. ``"email"``).
            trigger_trust: Trust level name of the triggering source.
            matched_patterns: Pattern keys that fired (BLOCK decisions).
            normalisation_flags: Sanitiser flags (BLOCK decisions).
            data_classification: Data classification label if applicable.
        """
        entry = DecisionEntry(
            entry_id=uuid.uuid4().hex[:12],
            timestamp=datetime.now(UTC).isoformat(),
            request_id=request_id,
            tool_name=tool_name,
            decision=decision,
            reason=reason,
            trigger_source=trigger_source,
            trigger_trust=trigger_trust,
            matched_patterns=list(matched_patterns or []),
            normalisation_flags=list(normalisation_flags or []),
            data_classification=data_classification,
        )
        with self._lock:
            self._entries.append(entry)
        self._persist(entry)

    def recent(
        self,
        n: int = 50,
        decision: str | None = None,
        tool: str | None = None,
        trust: str | None = None,
    ) -> list[DecisionEntry]:
        """Return recent decisions, newest first, with optional filters.

        Args:
            n: Maximum number of entries to return.
            decision: Filter to ``"BLOCK"``, ``"ALLOW"``, or ``"CONFIRM"``.
            tool: Case-insensitive substring match on ``tool_name``.
            trust: Filter to exact trust level name (e.g. ``"NONE"``).
        """
        with self._lock:
            entries = list(reversed(self._entries))
        if decision:
            entries = [e for e in entries if e.decision == decision.upper()]
        if tool:
            entries = [e for e in entries if tool.lower() in e.tool_name.lower()]
        if trust:
            entries = [e for e in entries if e.trigger_trust == trust.upper()]
        return entries[:n]

    def confirmation_queue(self) -> list[DecisionEntry]:
        """Return all CONFIRM-pending decisions, newest first."""
        return self.recent(n=100, decision="CONFIRM")

    def get(self, entry_id: str) -> DecisionEntry | None:
        """Return a single entry by its short ID, or ``None``."""
        with self._lock:
            for entry in self._entries:
                if entry.entry_id == entry_id:
                    return entry
        return None

    def stats(self) -> dict[str, int]:
        """Return aggregate counts: block, allow, confirm, total."""
        with self._lock:
            entries = list(self._entries)
        counts: dict[str, int] = {"BLOCK": 0, "ALLOW": 0, "CONFIRM": 0}
        for e in entries:
            counts[e.decision] = counts.get(e.decision, 0) + 1
        counts["total"] = sum(counts.values())
        return counts


# ─── HTML rendering ───────────────────────────────────────────────────────────


_DECISION_COLOR: dict[str, str] = {
    "BLOCK": "#e06c75",
    "ALLOW": "#98c379",
    "CONFIRM": "#e5c07b",
}

_CSS = (
    "* { box-sizing: border-box; margin: 0; padding: 0; }\n"
    "body { font-family: system-ui, sans-serif; font-size: 14px;\n"
    "       background: #1e1e2e; color: #cdd6f4; min-height: 100vh; }\n"
    "header { background: #181825; padding: 12px 20px;\n"
    "         border-bottom: 1px solid #313244;\n"
    "         display: flex; align-items: center; gap: 16px; }\n"
    "header h1 { font-size: 18px; font-weight: 700; color: #89dceb; }\n"
    ".stats-bar { display: flex; gap: 12px; flex-wrap: wrap; }\n"
    ".stat { padding: 4px 12px; border-radius: 4px;\n"
    "        background: #313244; font-size: 13px; }\n"
    ".stat.block { color: #e06c75; }\n"
    ".stat.allow { color: #98c379; }\n"
    ".stat.confirm { color: #e5c07b; }\n"
    "main { padding: 16px 20px; }\n"
    "section { margin-bottom: 24px; }\n"
    "h2 { font-size: 15px; font-weight: 600; margin-bottom: 10px;\n"
    "     color: #89b4fa; border-bottom: 1px solid #313244;\n"
    "     padding-bottom: 6px; }\n"
    ".filter-form { display: flex; gap: 8px; flex-wrap: wrap;\n"
    "               margin-bottom: 16px; }\n"
    ".filter-form select, .filter-form input {\n"
    "    background: #313244; color: #cdd6f4;\n"
    "    border: 1px solid #45475a; border-radius: 4px;\n"
    "    padding: 5px 8px; font-size: 13px; }\n"
    ".filter-form button { background: #89b4fa; color: #1e1e2e;\n"
    "    border: none; border-radius: 4px; padding: 5px 14px;\n"
    "    font-size: 13px; cursor: pointer; font-weight: 600; }\n"
    "table { width: 100%; border-collapse: collapse; font-size: 13px; }\n"
    "th { text-align: left; padding: 7px 10px; background: #181825;\n"
    "     color: #89b4fa; border-bottom: 2px solid #313244; }\n"
    "td { padding: 6px 10px; border-bottom: 1px solid #313244;\n"
    "     vertical-align: top; }\n"
    "tr:hover td { background: #27273e; }\n"
    ".dec { font-weight: 700; }\n"
    ".ts { white-space: nowrap; color: #a6adc8; font-size: 12px; }\n"
    ".tool { font-family: monospace; color: #cba6f7; }\n"
    ".src { color: #a6adc8; font-size: 12px; }\n"
    "details summary { cursor: pointer; color: #89b4fa; font-size: 12px;\n"
    "                  user-select: none; }\n"
    "details[open] summary { margin-bottom: 6px; }\n"
    ".prov { background: #181825; border-radius: 4px;\n"
    "        padding: 8px; font-size: 12px; line-height: 1.6; }\n"
    ".prov b { color: #a6e3a1; }\n"
    ".tag { display: inline-block; padding: 1px 6px; border-radius: 3px;\n"
    "       font-family: monospace; font-size: 11px; margin: 1px; }\n"
    ".tag.pattern { background: #3d2a45; color: #cba6f7; }\n"
    ".tag.flag { background: #2a3045; color: #89dceb; }\n"
    ".empty { color: #585b70; font-style: italic; padding: 16px 0; }\n"
    ".confirm-badge { background: #e5c07b; color: #1e1e2e;\n"
    "    font-size: 11px; font-weight: 700; border-radius: 10px;\n"
    "    padding: 1px 7px; margin-left: 8px; }\n"
)


def _e(text: object) -> str:
    """HTML-escape a value for safe insertion."""
    return _html.escape(str(text) if text is not None else "—")


def _render_tags(patterns: list[str], flags: list[str]) -> str:
    """Render pattern/flag names as coloured badge spans."""
    if not patterns and not flags:
        return "<em>none</em>"
    parts = [
        f'<span class="tag pattern">{_e(p)}</span>' for p in patterns
    ] + [
        f'<span class="tag flag">{_e(f)}</span>' for f in flags
    ]
    return " ".join(parts)


def _render_decision_row(entry: DecisionEntry) -> str:
    """Render a single table row with expandable provenance detail."""
    color = _DECISION_COLOR.get(entry.decision, "#a6adc8")
    ts = entry.timestamp[:19].replace("T", " ")
    src = _e(entry.trigger_source)
    trust = _e(entry.trigger_trust)

    prov = (
        f'<div><b>reason:</b> {_e(entry.reason)}</div>'
    )
    if entry.matched_patterns or entry.normalisation_flags:
        tags = _render_tags(entry.matched_patterns, entry.normalisation_flags)
        prov += f"<div><b>patterns / flags:</b> {tags}</div>"
    if entry.data_classification:
        prov += f"<div><b>classification:</b> {_e(entry.data_classification)}</div>"
    prov += f'<div><b>request id:</b> {_e(entry.request_id)}</div>'

    detail = (
        f'<details><summary>provenance ▾</summary>'
        f'<div class="prov">{prov}</div>'
        f'</details>'
    )
    return (
        f'<tr>'
        f'<td class="ts">{ts}</td>'
        f'<td class="tool">{_e(entry.tool_name)}</td>'
        f'<td class="dec" style="color:{color}">{entry.decision}</td>'
        f'<td class="src">{src}&nbsp;/&nbsp;{trust}</td>'
        f'<td>{detail}</td>'
        f'</tr>\n'
    )


def _render_dashboard(
    decisions: list[DecisionEntry],
    queue: list[DecisionEntry],
    stats: dict[str, int],
    filters: dict[str, str],
) -> str:
    """Render the complete dashboard HTML page."""
    rows = "".join(_render_decision_row(d) for d in decisions)
    queue_rows = "".join(_render_decision_row(d) for d in queue)

    # Active filter values for pre-populating the filter form
    dec_filter = filters.get("decision", "")
    tool_filter = filters.get("tool", "")
    trust_filter = filters.get("trust", "")

    def _opt(val: str, label: str, sel: str) -> str:
        selected = ' selected' if val == sel else ''
        return f'<option value="{val}"{selected}>{label}</option>'

    dec_opts = (
        _opt("", "All decisions", dec_filter)
        + _opt("BLOCK", "BLOCK", dec_filter)
        + _opt("ALLOW", "ALLOW", dec_filter)
        + _opt("CONFIRM", "CONFIRM", dec_filter)
    )
    trust_opts = (
        _opt("", "All trust levels", trust_filter)
        + _opt("NONE", "NONE", trust_filter)
        + _opt("TOOL", "TOOL", trust_filter)
        + _opt("AGENT", "AGENT", trust_filter)
        + _opt("SYSTEM", "SYSTEM", trust_filter)
        + _opt("USER", "USER", trust_filter)
        + _opt("OWNER", "OWNER", trust_filter)
    )

    queue_badge = ""
    if queue:
        queue_badge = f'<span class="confirm-badge">{len(queue)}</span>'

    decision_table = (
        rows
        if rows
        else '<tr><td colspan="5" class="empty">No decisions recorded yet.</td></tr>'
    )
    queue_table = (
        queue_rows
        if queue_rows
        else '<tr><td colspan="5" class="empty">Confirmation queue is empty.</td></tr>'
    )

    return (
        "<!DOCTYPE html>"
        '<html lang="en">'
        "<head>"
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>ShieldFlow Security Dashboard</title>"
        f"<style>{_CSS}</style>"
        "</head>"
        "<body>"
        "<header>"
        "<h1>🛡 ShieldFlow</h1>"
        '<div class="stats-bar">'
        f'<span class="stat">Logged: {stats.get("total", 0)}</span>'
        f'<span class="stat block">Blocked: {stats.get("BLOCK", 0)}</span>'
        f'<span class="stat allow">Allowed: {stats.get("ALLOW", 0)}</span>'
        f'<span class="stat confirm">Confirm: {stats.get("CONFIRM", 0)}</span>'
        "</div>"
        '<a href="/metrics/json" style="color:#89b4fa;font-size:12px;'
        'margin-left:auto;text-decoration:none">metrics JSON ↗</a>'
        "</header>"
        "<main>"
        '<section class="filters">'
        "<h2>Filters</h2>"
        '<form class="filter-form" method="get">'
        f'<select name="decision">{dec_opts}</select>'
        f'<select name="trust">{trust_opts}</select>'
        '<input name="tool" type="text" placeholder="Tool name"'
        f' value="{_e(tool_filter)}">'
        "<button type=\"submit\">Apply</button>"
        '<a href="/dashboard" style="padding:5px 10px;color:#89b4fa;'
        'font-size:13px;text-decoration:none">Clear</a>'
        "</form>"
        "</section>"
        f"<section>"
        f"<h2>⚠ Confirmation Queue{queue_badge}</h2>"
        "<table>"
        "<thead><tr>"
        "<th>Time</th><th>Tool</th><th>Decision</th>"
        "<th>Source / Trust</th><th>Provenance</th>"
        "</tr></thead>"
        f"<tbody>{queue_table}</tbody>"
        "</table>"
        "</section>"
        "<section>"
        "<h2>Recent Decisions</h2>"
        "<table>"
        "<thead><tr>"
        "<th>Time</th><th>Tool</th><th>Decision</th>"
        "<th>Source / Trust</th><th>Provenance</th>"
        "</tr></thead>"
        f"<tbody>{decision_table}</tbody>"
        "</table>"
        "</section>"
        "</main>"
        "</body></html>"
    )


# ─── Route registration ───────────────────────────────────────────────────────


def add_dashboard_routes(app: FastAPI, decision_log: DecisionLog) -> None:
    """Register dashboard routes on *app*.

    Args:
        app: The FastAPI application to add routes to.
        decision_log: The shared decision log populated by the server.
    """

    no_store_headers = {"Cache-Control": "no-store"}

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(
        decision: str | None = Query(default=None),
        tool: str | None = Query(default=None),
        trust: str | None = Query(default=None),
        n: int = Query(default=50, ge=1, le=200),
    ) -> HTMLResponse:
        """HTML security dashboard for decision triage.

        Query parameters:
            decision: Filter by BLOCK / ALLOW / CONFIRM.
            tool:     Case-insensitive substring match on tool name.
            trust:    Filter by exact trust level (NONE, USER, OWNER …).
            n:        Number of recent decisions to show (1–200, default 50).
        """
        decisions = decision_log.recent(
            n=n, decision=decision, tool=tool, trust=trust
        )
        queue = decision_log.confirmation_queue()
        stats = decision_log.stats()
        filters: dict[str, str] = {}
        if decision:
            filters["decision"] = decision
        if tool:
            filters["tool"] = tool
        if trust:
            filters["trust"] = trust
        return HTMLResponse(
            content=_render_dashboard(decisions, queue, stats, filters),
            headers=no_store_headers,
        )

    @app.get("/dashboard/api/decisions")
    async def api_decisions(
        decision: str | None = Query(default=None),
        tool: str | None = Query(default=None),
        trust: str | None = Query(default=None),
        n: int = Query(default=50, ge=1, le=200),
    ) -> JSONResponse:
        """JSON list of recent decisions (filterable).

        Same query parameters as ``GET /dashboard``.
        """
        entries = decision_log.recent(
            n=n, decision=decision, tool=tool, trust=trust
        )
        return JSONResponse(
            [e.to_dict() for e in entries],
            headers=no_store_headers,
        )

    @app.get("/dashboard/api/queue")
    async def api_queue() -> JSONResponse:
        """JSON list of CONFIRM-pending decisions (newest first)."""
        return JSONResponse(
            [e.to_dict() for e in decision_log.confirmation_queue()],
            headers=no_store_headers,
        )
