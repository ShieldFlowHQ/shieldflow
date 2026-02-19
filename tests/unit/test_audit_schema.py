"""Unit tests for the AuditLogger schema v2.

Verifies:
- Every event type carries ``schema_version``
- ``log_blocked`` includes full provenance fields
- ``log_allowed`` and ``log_confirmation_required`` emit correct structure
- Output is valid JSONL (one parseable JSON object per line)
- ``matched_patterns`` and ``normalisation_flags`` are serialised as lists
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from shieldflow.proxy.audit import AUDIT_SCHEMA_VERSION, AuditLogger

# ─── Helpers ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def logger(tmp_path: Path) -> tuple[AuditLogger, Path]:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(log_path))
    yield log, log_path  # type: ignore[misc]
    log.close()


def read_events(log_path: Path) -> list[dict[str, Any]]:
    """Read all JSONL records from the audit log file."""
    with open(log_path) as f:
        return [json.loads(line) for line in f if line.strip()]


# ─── Schema version ───────────────────────────────────────────────────────────


class TestSchemaVersion:
    """Every event type must include schema_version."""

    def test_request_has_schema_version(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_request(
            request_id="req-1",
            model="gpt-4",
            message_count=2,
            trust_summary={"USER": 1},
        )
        events = read_events(path)
        assert events[0]["schema_version"] == AUDIT_SCHEMA_VERSION

    def test_blocked_has_schema_version(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_blocked(
            request_id="req-1",
            tool_name="exec",
            reason="Injection detected",
            trigger_trust="NONE",
        )
        events = read_events(path)
        assert events[0]["schema_version"] == AUDIT_SCHEMA_VERSION

    def test_allowed_has_schema_version(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_allowed(
            request_id="req-1",
            tool_name="email.send",
            trigger_trust="USER",
        )
        events = read_events(path)
        assert events[0]["schema_version"] == AUDIT_SCHEMA_VERSION

    def test_confirmation_required_has_schema_version(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_confirmation_required(
            request_id="req-1",
            tool_name="file.delete",
            reason="Sensitive path",
            trigger_trust="USER",
        )
        events = read_events(path)
        assert events[0]["schema_version"] == AUDIT_SCHEMA_VERSION

    def test_response_has_schema_version(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_response(
            request_id="req-1",
            blocked_count=1,
            allowed_count=2,
            model="gpt-4",
        )
        events = read_events(path)
        assert events[0]["schema_version"] == AUDIT_SCHEMA_VERSION

    def test_auth_failure_has_schema_version(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_auth_failure(request_id="req-1", reason="Bad token")
        events = read_events(path)
        assert events[0]["schema_version"] == AUDIT_SCHEMA_VERSION


# ─── Blocked event provenance ─────────────────────────────────────────────────


class TestBlockedEventProvenance:
    """log_blocked must include machine-parseable provenance fields."""

    def test_decision_field_is_block(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_blocked(
            request_id="req-1",
            tool_name="exec",
            reason="Injection",
            trigger_trust="NONE",
        )
        event = read_events(path)[0]
        assert event["decision"] == "BLOCK"
        assert event["event"] == "blocked"

    def test_trigger_source_included(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_blocked(
            request_id="req-1",
            tool_name="exec",
            reason="Injection",
            trigger_trust="NONE",
            trigger_source="email",
        )
        event = read_events(path)[0]
        assert event["trigger_source"] == "email"

    def test_matched_patterns_serialised_as_list(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        patterns = ["pattern:ignore_previous_instructions", "pattern:execute_following"]
        log.log_blocked(
            request_id="req-1",
            tool_name="exec",
            reason="Injection",
            trigger_trust="NONE",
            matched_patterns=patterns,
        )
        event = read_events(path)[0]
        assert isinstance(event["matched_patterns"], list)
        assert event["matched_patterns"] == patterns

    def test_normalisation_flags_serialised_as_list(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_blocked(
            request_id="req-1",
            tool_name="exec",
            reason="Encoded injection",
            trigger_trust="NONE",
            normalisation_flags=["base64_injection", "homoglyphs"],
        )
        event = read_events(path)[0]
        assert isinstance(event["normalisation_flags"], list)
        assert "base64_injection" in event["normalisation_flags"]

    def test_empty_patterns_and_flags_default_to_lists(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_blocked(
            request_id="req-1",
            tool_name="exec",
            reason="Injection",
            trigger_trust="NONE",
        )
        event = read_events(path)[0]
        assert event["matched_patterns"] == []
        assert event["normalisation_flags"] == []

    def test_data_classification_included(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_blocked(
            request_id="req-1",
            tool_name="data.bulk_export",
            reason="Untrusted trigger",
            trigger_trust="NONE",
            data_classification="confidential",
        )
        event = read_events(path)[0]
        assert event["data_classification"] == "confidential"

    def test_full_provenance_round_trip(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        """All provenance fields survive JSON serialisation."""
        log, path = logger
        log.log_blocked(
            request_id="req-abc",
            tool_name="email.send",
            reason="base64-encoded injection detected",
            trigger_trust="NONE",
            trigger_source="web_fetch",
            matched_patterns=["normalisation:base64_injection"],
            normalisation_flags=["base64_injection"],
            data_classification=None,
        )
        event = read_events(path)[0]
        assert event["schema_version"] == AUDIT_SCHEMA_VERSION
        assert event["event"] == "blocked"
        assert event["decision"] == "BLOCK"
        assert event["tool_name"] == "email.send"
        assert event["trigger_source"] == "web_fetch"
        assert event["trigger_trust"] == "NONE"
        assert event["matched_patterns"] == ["normalisation:base64_injection"]
        assert event["normalisation_flags"] == ["base64_injection"]
        assert event["data_classification"] is None


# ─── Allowed event ────────────────────────────────────────────────────────────


class TestAllowedEvent:
    """log_allowed must emit a lightweight, correctly-typed event."""

    def test_event_type_and_decision(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_allowed(
            request_id="req-1",
            tool_name="email.send",
            trigger_trust="USER",
            trigger_source="user_chat",
        )
        event = read_events(path)[0]
        assert event["event"] == "allowed"
        assert event["decision"] == "ALLOW"

    def test_trigger_fields_present(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_allowed(
            request_id="req-1",
            tool_name="file.read",
            trigger_trust="USER",
            trigger_source="user_chat",
            data_classification="internal",
        )
        event = read_events(path)[0]
        assert event["trigger_trust"] == "USER"
        assert event["trigger_source"] == "user_chat"
        assert event["data_classification"] == "internal"


# ─── Confirmation-required event ──────────────────────────────────────────────


class TestConfirmationRequiredEvent:
    """log_confirmation_required must emit a correctly-typed event."""

    def test_event_type_and_decision(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_confirmation_required(
            request_id="req-1",
            tool_name="file.delete",
            reason="Sensitive path requires confirmation",
            trigger_trust="USER",
        )
        event = read_events(path)[0]
        assert event["event"] == "confirmation_required"
        assert event["decision"] == "CONFIRM"

    def test_reason_field_present(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        msg = "Action targets sensitive data"
        log.log_confirmation_required(
            request_id="req-1",
            tool_name="file.delete",
            reason=msg,
            trigger_trust="USER",
            trigger_source="user_chat",
            data_classification="sensitive",
        )
        event = read_events(path)[0]
        assert event["reason"] == msg
        assert event["data_classification"] == "sensitive"


# ─── JSONL format ─────────────────────────────────────────────────────────────


class TestJsonlFormat:
    """Output must be valid JSONL (one parseable object per line)."""

    def test_multiple_events_each_valid_json(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_request(
            request_id="r1", model="gpt-4", message_count=1,
            trust_summary={"USER": 1},
        )
        log.log_blocked(
            request_id="r1", tool_name="exec",
            reason="injection", trigger_trust="NONE",
        )
        log.log_allowed(
            request_id="r1", tool_name="email.send", trigger_trust="USER",
        )
        log.log_response(
            request_id="r1", blocked_count=1, allowed_count=1, model="gpt-4",
        )
        log.close()

        with open(path) as f:
            lines = [line for line in f if line.strip()]

        assert len(lines) == 4
        for line in lines:
            obj = json.loads(line)
            assert "schema_version" in obj
            assert "event" in obj
            assert "timestamp" in obj
            assert "request_id" in obj

    def test_no_trailing_newline_inside_records(
        self, logger: tuple[AuditLogger, Path]
    ) -> None:
        log, path = logger
        log.log_auth_failure(request_id="r1", reason="bad token")
        log.close()
        with open(path) as f:
            raw = f.read()
        # Each record is one line; no embedded newlines within a record
        lines = [line for line in raw.splitlines() if line.strip()]
        assert len(lines) == 1
        json.loads(lines[0])  # must parse as valid JSON
