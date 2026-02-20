"""JSON Lines audit logger for the ShieldFlow proxy — schema v2.

Every request, blocked action, allowed action, and response is recorded
as a single JSON object per line (JSONL format) for easy ingestion into
log aggregators such as Loki, Splunk, or plain ``grep``.

All events include a ``schema_version`` field for forward compatibility.

Example log entries (one JSON object per line)::

    # Incoming request
    {"schema_version": "2", "event": "request", "timestamp": "...",
     "request_id": "abc-123", "model": "gpt-4", "message_count": 3,
     "trust_summary": {"USER": 1, "NONE": 2}}

    # Tool call blocked — includes full provenance
    {"schema_version": "2", "event": "blocked", "timestamp": "...",
     "request_id": "abc-123", "tool_name": "exec", "decision": "BLOCK",
     "reason": "...", "trigger_source": "email", "trigger_trust": "NONE",
     "matched_patterns": ["pattern:ignore_previous_instructions"],
     "normalisation_flags": ["base64_injection"],
     "data_classification": null}

    # Tool call allowed — lightweight provenance
    {"schema_version": "2", "event": "allowed", "timestamp": "...",
     "request_id": "abc-123", "tool_name": "email.send",
     "decision": "ALLOW", "trigger_source": "user_chat",
     "trigger_trust": "USER", "data_classification": null}

    # Tool call needs operator confirmation
    {"schema_version": "2", "event": "confirmation_required",
     "timestamp": "...", "request_id": "abc-123",
     "tool_name": "file.delete", "decision": "CONFIRM",
     "reason": "...", "trigger_source": "user_chat",
     "trigger_trust": "USER", "data_classification": "sensitive"}

    # Response summary after all tool calls validated
    {"schema_version": "2", "event": "response", "timestamp": "...",
     "request_id": "abc-123", "blocked_count": 1, "allowed_count": 2,
     "model": "gpt-4"}
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

#: Audit schema version.  Increment when the event structure changes in a
#: backward-incompatible way so downstream consumers can version-gate.
AUDIT_SCHEMA_VERSION = "2"


class AuditLogger:
    """Append-only JSONL audit logger.

    Writes one JSON object per line to a file, or to stderr when no
    path is configured (useful for container deployments where stderr
    is collected by the orchestrator).

    The logger is thread-safe for line-buffered writes but does not
    support concurrent file rotation. Use an external log shipper
    (logrotate, vector, fluentd) for production log management.
    """

    def __init__(self, path: str | None = None) -> None:
        """Initialise the audit logger.

        Args:
            path: Absolute or relative path to the audit log file.
                  Directory will be created if it does not exist.
                  Pass ``None`` to write to stderr.
        """
        self._path = path
        self._file: IO[str] | None = None

        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            # Line-buffered (buffering=1) so each record is flushed immediately
            self._file = open(path, "a", buffering=1, encoding="utf-8")

    # ------------------------------------------------------------------ #
    # Public logging methods                                               #
    # ------------------------------------------------------------------ #

    def log_request(
        self,
        request_id: str,
        model: str,
        message_count: int,
        trust_summary: dict[str, int],
    ) -> None:
        """Log an incoming proxy request.

        Args:
            request_id: Unique request identifier (UUID).
            model: Requested LLM model name.
            message_count: Number of messages in the conversation.
            trust_summary: Mapping of trust level name → block count.
        """
        self._write(
            {
                "event": "request",
                "timestamp": self._now(),
                "request_id": request_id,
                "model": model,
                "message_count": message_count,
                "trust_summary": trust_summary,
            }
        )

    def log_blocked(
        self,
        request_id: str,
        tool_name: str,
        reason: str,
        trigger_trust: str,
        trigger_source: str | None = None,
        matched_patterns: list[str] | None = None,
        normalisation_flags: list[str] | None = None,
        data_classification: str | None = None,
    ) -> None:
        """Log a blocked tool call with full decision provenance.

        Args:
            request_id: Unique request identifier.
            tool_name: Name of the blocked tool/function.
            reason: Human-readable explanation of why it was blocked.
            trigger_trust: Trust level name of the triggering source.
            trigger_source: Source identifier (e.g. ``"email"``,
                ``"user_chat"``, ``"web_fetch"``).
            matched_patterns: Pattern keys from ``NAMED_INJECTION_PATTERNS``
                that fired, prefixed ``"pattern:"``; sanitiser-detected
                encodings are prefixed ``"normalisation:"``.
            normalisation_flags: Raw flags from the sanitiser
                (e.g. ``["base64_injection", "homoglyphs"]``).
            data_classification: Data classification label when applicable.
        """
        self._write(
            {
                "event": "blocked",
                "timestamp": self._now(),
                "request_id": request_id,
                "tool_name": tool_name,
                "decision": "BLOCK",
                "reason": reason,
                "trigger_source": trigger_source,
                "trigger_trust": trigger_trust,
                "matched_patterns": matched_patterns or [],
                "normalisation_flags": normalisation_flags or [],
                "data_classification": data_classification,
            }
        )

    def log_allowed(
        self,
        request_id: str,
        tool_name: str,
        trigger_trust: str,
        trigger_source: str | None = None,
        data_classification: str | None = None,
    ) -> None:
        """Log an allowed tool call.

        Provides a complete audit trail so operators can reconstruct
        the full decision sequence for any request.

        Args:
            request_id: Unique request identifier.
            tool_name: Name of the allowed tool/function.
            trigger_trust: Trust level name of the triggering source.
            trigger_source: Source identifier.
            data_classification: Data classification label when applicable.
        """
        self._write(
            {
                "event": "allowed",
                "timestamp": self._now(),
                "request_id": request_id,
                "tool_name": tool_name,
                "decision": "ALLOW",
                "trigger_source": trigger_source,
                "trigger_trust": trigger_trust,
                "data_classification": data_classification,
            }
        )

    def log_confirmation_required(
        self,
        request_id: str,
        tool_name: str,
        reason: str,
        trigger_trust: str,
        trigger_source: str | None = None,
        data_classification: str | None = None,
    ) -> None:
        """Log a tool call that requires operator confirmation.

        Args:
            request_id: Unique request identifier.
            tool_name: Name of the tool requiring confirmation.
            reason: Human-readable explanation of why confirmation is needed.
            trigger_trust: Trust level name of the triggering source.
            trigger_source: Source identifier.
            data_classification: Data classification label when applicable.
        """
        self._write(
            {
                "event": "confirmation_required",
                "timestamp": self._now(),
                "request_id": request_id,
                "tool_name": tool_name,
                "decision": "CONFIRM",
                "reason": reason,
                "trigger_source": trigger_source,
                "trigger_trust": trigger_trust,
                "data_classification": data_classification,
            }
        )

    def log_response(
        self,
        request_id: str,
        blocked_count: int,
        allowed_count: int,
        model: str,
    ) -> None:
        """Log a completed response (after tool call validation).

        Args:
            request_id: Unique request identifier.
            blocked_count: Number of tool calls that were blocked.
            allowed_count: Number of tool calls that were allowed.
            model: Model name reported by the upstream provider.
        """
        self._write(
            {
                "event": "response",
                "timestamp": self._now(),
                "request_id": request_id,
                "blocked_count": blocked_count,
                "allowed_count": allowed_count,
                "model": model,
            }
        )

    def log_auth_failure(self, request_id: str, reason: str) -> None:
        """Log an authentication failure.

        Args:
            request_id: Unique request identifier.
            reason: Why authentication failed.
        """
        self._write(
            {
                "event": "auth_failure",
                "timestamp": self._now(),
                "request_id": request_id,
                "reason": reason,
            }
        )

    def close(self) -> None:
        """Flush and close the log file (no-op for stderr)."""
        if self._file and not self._file.closed:
            self._file.flush()
            self._file.close()

    def __del__(self) -> None:
        """Ensure the file is closed on garbage collection."""
        try:
            self.close()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _write(self, record: dict[str, Any]) -> None:
        """Serialise and write a single JSONL record.

        Prepends ``schema_version`` to every record so consumers can
        detect schema changes without inspecting the event type.
        """
        full = {"schema_version": AUDIT_SCHEMA_VERSION, **record}
        line = json.dumps(full, default=str, ensure_ascii=False)
        if self._file:
            self._file.write(line + "\n")
        else:
            print(line, file=sys.stderr)

    @staticmethod
    def _now() -> str:
        """Return current UTC time in ISO-8601 format."""
        return datetime.now(UTC).isoformat()
