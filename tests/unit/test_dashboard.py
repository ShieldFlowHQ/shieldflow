"""Unit tests for the DecisionLog and security dashboard endpoints.

Covers:
- DecisionLog.record() / recent() / confirmation_queue() / get() / stats()
- Filtering by decision type, tool name, trust level
- Ring-buffer eviction (maxlen)
- Thread safety
- GET /dashboard returns HTML with correct structure
- GET /dashboard?decision=BLOCK filter
- GET /dashboard/api/decisions JSON response
- GET /dashboard/api/queue JSON response
- Acceptance criteria: provenance visible, confirm queue surfaced, filters work
"""

from __future__ import annotations

import threading
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from shieldflow.proxy.audit import AuditLogger
from shieldflow.proxy.config import ProxyConfig, UpstreamConfig
from shieldflow.proxy.dashboard import DecisionLog
from shieldflow.proxy.server import create_app

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def log() -> DecisionLog:
    return DecisionLog(maxlen=20)


def _cfg() -> ProxyConfig:
    return ProxyConfig(
        upstream=UpstreamConfig(url="https://api.openai.com", api_key="sk-t"),
        api_keys=[],
    )


def _app(dl: DecisionLog) -> Any:
    return create_app(_cfg(), audit=AuditLogger(path=None), decision_log=dl)


def _add(
    dl: DecisionLog,
    decision: str = "ALLOW",
    tool: str = "email.send",
    trust: str = "USER",
    source: str = "user_chat",
    patterns: list[str] | None = None,
    flags: list[str] | None = None,
) -> None:
    dl.record(
        request_id="req-test",
        tool_name=tool,
        decision=decision,
        reason=f"test reason for {decision}",
        trigger_source=source,
        trigger_trust=trust,
        matched_patterns=patterns,
        normalisation_flags=flags,
    )


# ─── DecisionLog.record ────────────────────────────────────────────────────────


class TestDecisionLogRecord:
    def test_record_populates_entry(self, log: DecisionLog) -> None:
        _add(log, decision="BLOCK", tool="exec", trust="NONE")
        entries = log.recent()
        assert len(entries) == 1
        e = entries[0]
        assert e.tool_name == "exec"
        assert e.decision == "BLOCK"
        assert e.trigger_trust == "NONE"

    def test_entry_has_unique_id(self, log: DecisionLog) -> None:
        _add(log)
        _add(log)
        ids = {e.entry_id for e in log.recent()}
        assert len(ids) == 2

    def test_entry_has_timestamp(self, log: DecisionLog) -> None:
        _add(log)
        e = log.recent()[0]
        assert "T" in e.timestamp or "+" in e.timestamp

    def test_patterns_and_flags_stored(self, log: DecisionLog) -> None:
        _add(
            log,
            decision="BLOCK",
            patterns=["pattern:ignore_previous_instructions"],
            flags=["base64_injection"],
        )
        e = log.recent()[0]
        assert e.matched_patterns == ["pattern:ignore_previous_instructions"]
        assert e.normalisation_flags == ["base64_injection"]

    def test_none_patterns_becomes_empty_list(self, log: DecisionLog) -> None:
        _add(log, patterns=None, flags=None)
        e = log.recent()[0]
        assert e.matched_patterns == []
        assert e.normalisation_flags == []

    def test_ring_buffer_evicts_oldest(self) -> None:
        small_log = DecisionLog(maxlen=3)
        for i in range(5):
            small_log.record(
                request_id=f"r{i}",
                tool_name=f"tool{i}",
                decision="ALLOW",
                reason="ok",
            )
        entries = small_log.recent(n=10)
        assert len(entries) == 3
        tools = {e.tool_name for e in entries}
        assert "tool4" in tools
        assert "tool0" not in tools


# ─── DecisionLog.recent (filtering) ───────────────────────────────────────────


class TestDecisionLogFiltering:
    def test_filter_by_decision(self, log: DecisionLog) -> None:
        _add(log, decision="BLOCK")
        _add(log, decision="ALLOW")
        _add(log, decision="CONFIRM")
        blocks = log.recent(decision="BLOCK")
        assert all(e.decision == "BLOCK" for e in blocks)
        assert len(blocks) == 1

    def test_filter_by_decision_case_insensitive(
        self, log: DecisionLog
    ) -> None:
        _add(log, decision="BLOCK")
        assert len(log.recent(decision="block")) == 1

    def test_filter_by_tool_substring(self, log: DecisionLog) -> None:
        _add(log, tool="email.send")
        _add(log, tool="file.read")
        _add(log, tool="email.reply")
        results = log.recent(tool="email")
        assert len(results) == 2
        assert all("email" in e.tool_name for e in results)

    def test_filter_by_trust(self, log: DecisionLog) -> None:
        _add(log, trust="NONE")
        _add(log, trust="USER")
        _add(log, trust="OWNER")
        results = log.recent(trust="NONE")
        assert all(e.trigger_trust == "NONE" for e in results)
        assert len(results) == 1

    def test_filter_by_trust_case_insensitive(
        self, log: DecisionLog
    ) -> None:
        _add(log, trust="NONE")
        assert len(log.recent(trust="none")) == 1

    def test_combined_filters(self, log: DecisionLog) -> None:
        _add(log, decision="BLOCK", tool="exec", trust="NONE")
        _add(log, decision="BLOCK", tool="file.read", trust="NONE")
        _add(log, decision="ALLOW", tool="exec", trust="USER")
        results = log.recent(decision="BLOCK", tool="exec", trust="NONE")
        assert len(results) == 1
        assert results[0].tool_name == "exec"

    def test_n_limits_results(self, log: DecisionLog) -> None:
        for _ in range(10):
            _add(log)
        assert len(log.recent(n=3)) == 3

    def test_newest_first(self, log: DecisionLog) -> None:
        for i in range(3):
            log.record(
                request_id=f"r{i}",
                tool_name=f"t{i}",
                decision="ALLOW",
                reason="ok",
            )
        entries = log.recent()
        assert entries[0].tool_name == "t2"
        assert entries[-1].tool_name == "t0"


# ─── confirmation_queue / get / stats ─────────────────────────────────────────


class TestDecisionLogMisc:
    def test_confirmation_queue_returns_confirm_only(
        self, log: DecisionLog
    ) -> None:
        _add(log, decision="BLOCK")
        _add(log, decision="CONFIRM")
        _add(log, decision="ALLOW")
        queue = log.confirmation_queue()
        assert len(queue) == 1
        assert queue[0].decision == "CONFIRM"

    def test_confirmation_queue_empty_when_none(
        self, log: DecisionLog
    ) -> None:
        _add(log, decision="BLOCK")
        assert log.confirmation_queue() == []

    def test_get_by_entry_id(self, log: DecisionLog) -> None:
        _add(log, decision="BLOCK", tool="exec")
        entry_id = log.recent()[0].entry_id
        found = log.get(entry_id)
        assert found is not None
        assert found.tool_name == "exec"

    def test_get_missing_returns_none(self, log: DecisionLog) -> None:
        assert log.get("nonexistent") is None

    def test_stats_counts_correctly(self, log: DecisionLog) -> None:
        _add(log, decision="BLOCK")
        _add(log, decision="BLOCK")
        _add(log, decision="ALLOW")
        _add(log, decision="CONFIRM")
        s = log.stats()
        assert s["BLOCK"] == 2
        assert s["ALLOW"] == 1
        assert s["CONFIRM"] == 1
        assert s["total"] == 4

    def test_stats_empty_log(self, log: DecisionLog) -> None:
        s = log.stats()
        assert s["total"] == 0

    def test_to_dict_roundtrip(self, log: DecisionLog) -> None:
        _add(
            log,
            decision="BLOCK",
            tool="exec",
            trust="NONE",
            source="email",
            patterns=["pattern:p1"],
            flags=["base64_injection"],
        )
        d = log.recent()[0].to_dict()
        assert d["decision"] == "BLOCK"
        assert d["tool_name"] == "exec"
        assert d["matched_patterns"] == ["pattern:p1"]
        assert d["normalisation_flags"] == ["base64_injection"]


# ─── Thread safety ─────────────────────────────────────────────────────────────


class TestDecisionLogThreadSafety:
    def test_concurrent_record(self, log: DecisionLog) -> None:
        dl = DecisionLog(maxlen=500)
        threads = [
            threading.Thread(
                target=lambda: _add(dl, decision="ALLOW")
            )
            for _ in range(100)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert dl.stats()["total"] == 100


# ─── Dashboard HTML endpoint ───────────────────────────────────────────────────


class TestDashboardEndpoint:
    @pytest.mark.asyncio
    async def test_dashboard_returns_200_html(
        self, log: DecisionLog
    ) -> None:
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_dashboard_contains_shieldflow_header(
        self, log: DecisionLog
    ) -> None:
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard")
        assert "ShieldFlow" in resp.text

    @pytest.mark.asyncio
    async def test_dashboard_shows_decision_rows(
        self, log: DecisionLog
    ) -> None:
        _add(log, decision="BLOCK", tool="exec", trust="NONE")
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard")
        assert "exec" in resp.text
        assert "BLOCK" in resp.text

    @pytest.mark.asyncio
    async def test_dashboard_shows_provenance_detail(
        self, log: DecisionLog
    ) -> None:
        """Operators can see why a request was blocked (acceptance criterion 1)."""
        _add(
            log,
            decision="BLOCK",
            tool="exec",
            patterns=["pattern:ignore_previous_instructions"],
            flags=["base64_injection"],
        )
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard")
        assert "ignore_previous_instructions" in resp.text
        assert "base64_injection" in resp.text
        assert "provenance" in resp.text

    @pytest.mark.asyncio
    async def test_dashboard_shows_confirm_queue(
        self, log: DecisionLog
    ) -> None:
        """CONFIRM actions are surfaced in the queue (acceptance criterion 2)."""
        _add(log, decision="CONFIRM", tool="file.delete")
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard")
        html = resp.text
        assert "Confirmation Queue" in html
        assert "file.delete" in html

    @pytest.mark.asyncio
    async def test_dashboard_filter_by_decision(
        self, log: DecisionLog
    ) -> None:
        """Filter form filters by decision type (acceptance criterion 3)."""
        _add(log, decision="BLOCK", tool="exec")
        _add(log, decision="ALLOW", tool="email.send")
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard?decision=BLOCK")
        assert "exec" in resp.text
        # ALLOW decision's tool should not appear in the filtered view
        assert "email.send" not in resp.text

    @pytest.mark.asyncio
    async def test_dashboard_filter_by_tool(
        self, log: DecisionLog
    ) -> None:
        """Filter by tool name (acceptance criterion 3)."""
        _add(log, tool="exec")
        _add(log, tool="file.read")
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard?tool=exec")
        assert "exec" in resp.text
        assert "file.read" not in resp.text

    @pytest.mark.asyncio
    async def test_dashboard_empty_state(
        self, log: DecisionLog
    ) -> None:
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard")
        assert "No decisions recorded" in resp.text


# ─── JSON API endpoints ────────────────────────────────────────────────────────


class TestDashboardApiEndpoints:
    @pytest.mark.asyncio
    async def test_api_decisions_returns_json_list(
        self, log: DecisionLog
    ) -> None:
        _add(log, decision="BLOCK")
        _add(log, decision="ALLOW")
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard/api/decisions")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 2

    @pytest.mark.asyncio
    async def test_api_decisions_filter_by_decision(
        self, log: DecisionLog
    ) -> None:
        _add(log, decision="BLOCK")
        _add(log, decision="ALLOW")
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard/api/decisions?decision=BLOCK")
        data = resp.json()
        assert all(d["decision"] == "BLOCK" for d in data)

    @pytest.mark.asyncio
    async def test_api_decisions_entry_has_required_fields(
        self, log: DecisionLog
    ) -> None:
        _add(
            log,
            decision="BLOCK",
            tool="exec",
            trust="NONE",
            source="email",
        )
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard/api/decisions")
        entry = resp.json()[0]
        for field in [
            "entry_id", "timestamp", "request_id", "tool_name",
            "decision", "reason", "trigger_source", "trigger_trust",
            "matched_patterns", "normalisation_flags",
        ]:
            assert field in entry, f"Missing field: {field}"

    @pytest.mark.asyncio
    async def test_api_queue_returns_confirm_only(
        self, log: DecisionLog
    ) -> None:
        _add(log, decision="BLOCK")
        _add(log, decision="CONFIRM")
        _add(log, decision="ALLOW")
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard/api/queue")
        data = resp.json()
        assert len(data) == 1
        assert data[0]["decision"] == "CONFIRM"

    @pytest.mark.asyncio
    async def test_api_queue_empty_when_no_confirms(
        self, log: DecisionLog
    ) -> None:
        _add(log, decision="ALLOW")
        app = _app(log)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/dashboard/api/queue")
        assert resp.json() == []
