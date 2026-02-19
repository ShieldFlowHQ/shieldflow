"""Unit tests for MetricsCollector and the proxy metrics endpoints.

Covers:
- request and decision recording
- snapshot() structure and aggregations
- prometheus_text() format validity
- /metrics and /metrics/json endpoints
- thread safety (basic concurrent increment check)
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from shieldflow.proxy.audit import AuditLogger
from shieldflow.proxy.config import ProxyConfig, UpstreamConfig
from shieldflow.proxy.metrics import MetricsCollector, _escape_label
from shieldflow.proxy.server import create_app

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def mc() -> MetricsCollector:
    return MetricsCollector()


def open_config() -> ProxyConfig:
    return ProxyConfig(
        upstream=UpstreamConfig(url="https://api.openai.com", api_key="sk-test"),
        api_keys=[],
    )


# ─── Recording ─────────────────────────────────────────────────────────────────


class TestRecording:
    def test_requests_total_increments(self, mc: MetricsCollector) -> None:
        assert mc.snapshot()["requests_total"] == 0
        mc.record_request()
        mc.record_request()
        assert mc.snapshot()["requests_total"] == 2

    def test_decision_increments_by_type(self, mc: MetricsCollector) -> None:
        mc.record_decision("BLOCK", "exec", "NONE")
        mc.record_decision("ALLOW", "email.send", "USER")
        mc.record_decision("ALLOW", "email.send", "USER")
        snap = mc.snapshot()
        assert snap["decisions"]["block_total"] == 1
        assert snap["decisions"]["allow_total"] == 2
        assert snap["decisions"]["confirm_total"] == 0

    def test_confirm_decision_counted(self, mc: MetricsCollector) -> None:
        mc.record_decision("CONFIRM", "file.delete", "USER")
        snap = mc.snapshot()
        assert snap["decisions"]["confirm_total"] == 1
        assert snap["decisions"]["block_total"] == 0

    def test_matched_patterns_accumulated(self, mc: MetricsCollector) -> None:
        mc.record_decision(
            "BLOCK",
            "exec",
            "NONE",
            matched_patterns=["pattern:ignore_previous_instructions"],
        )
        mc.record_decision(
            "BLOCK",
            "exec",
            "NONE",
            matched_patterns=["pattern:ignore_previous_instructions"],
        )
        mc.record_decision(
            "BLOCK",
            "email.send",
            "NONE",
            matched_patterns=["normalisation:base64_injection"],
        )
        snap = mc.snapshot()
        patterns = dict(snap["top_blocked_patterns"])
        assert patterns["pattern:ignore_previous_instructions"] == 2
        assert patterns["normalisation:base64_injection"] == 1

    def test_normalisation_flags_accumulated(
        self, mc: MetricsCollector
    ) -> None:
        mc.record_decision(
            "BLOCK",
            "exec",
            "NONE",
            normalisation_flags=["base64_injection", "homoglyphs"],
        )
        mc.record_decision(
            "BLOCK",
            "exec",
            "NONE",
            normalisation_flags=["base64_injection"],
        )
        snap = mc.snapshot()
        flags = dict(snap["top_normalisation_flags"])
        assert flags["base64_injection"] == 2
        assert flags["homoglyphs"] == 1

    def test_no_patterns_or_flags_is_fine(
        self, mc: MetricsCollector
    ) -> None:
        mc.record_decision("ALLOW", "file.read", "USER")
        snap = mc.snapshot()
        assert snap["top_blocked_patterns"] == []
        assert snap["top_normalisation_flags"] == []


# ─── Snapshot structure ────────────────────────────────────────────────────────


class TestSnapshot:
    def test_empty_snapshot_structure(self, mc: MetricsCollector) -> None:
        snap = mc.snapshot()
        assert "requests_total" in snap
        assert "decisions" in snap
        assert "decisions_by_tool" in snap
        assert "top_blocked_patterns" in snap
        assert "top_normalisation_flags" in snap
        assert snap["decisions"]["block_total"] == 0
        assert snap["decisions"]["allow_total"] == 0
        assert snap["decisions"]["confirm_total"] == 0

    def test_decisions_by_tool_grouping(self, mc: MetricsCollector) -> None:
        mc.record_decision("BLOCK", "exec", "NONE")
        mc.record_decision("ALLOW", "exec", "USER")
        mc.record_decision("ALLOW", "email.send", "USER")
        snap = mc.snapshot()
        by_tool = snap["decisions_by_tool"]
        assert by_tool["exec"]["BLOCK"] == 1
        assert by_tool["exec"]["ALLOW"] == 1
        assert by_tool["email.send"]["ALLOW"] == 1

    def test_top_blocked_patterns_sorted_desc(
        self, mc: MetricsCollector
    ) -> None:
        mc.record_decision(
            "BLOCK", "exec", "NONE",
            matched_patterns=["p:a", "p:b"],
        )
        mc.record_decision(
            "BLOCK", "exec", "NONE",
            matched_patterns=["p:a"],
        )
        snap = mc.snapshot()
        patterns = snap["top_blocked_patterns"]
        assert patterns[0][0] == "p:a"
        assert patterns[0][1] == 2
        assert patterns[1][1] == 1

    def test_top_blocked_patterns_capped_at_20(
        self, mc: MetricsCollector
    ) -> None:
        for i in range(25):
            mc.record_decision(
                "BLOCK", "exec", "NONE",
                matched_patterns=[f"pattern:p{i}"],
            )
        snap = mc.snapshot()
        assert len(snap["top_blocked_patterns"]) == 20


# ─── Prometheus text format ────────────────────────────────────────────────────


class TestPrometheusText:
    def test_contains_required_metric_names(
        self, mc: MetricsCollector
    ) -> None:
        text = mc.prometheus_text()
        assert "shieldflow_requests_total" in text
        assert "shieldflow_decisions_total" in text
        assert "shieldflow_blocked_patterns_total" in text
        assert "shieldflow_normalisation_flags_total" in text

    def test_contains_help_and_type_lines(
        self, mc: MetricsCollector
    ) -> None:
        text = mc.prometheus_text()
        assert "# HELP shieldflow_requests_total" in text
        assert "# TYPE shieldflow_requests_total counter" in text

    def test_request_counter_in_output(
        self, mc: MetricsCollector
    ) -> None:
        mc.record_request()
        mc.record_request()
        text = mc.prometheus_text()
        assert "shieldflow_requests_total 2" in text

    def test_decision_labels_in_output(
        self, mc: MetricsCollector
    ) -> None:
        mc.record_decision("BLOCK", "exec", "NONE")
        text = mc.prometheus_text()
        assert 'decision="BLOCK"' in text
        assert 'tool="exec"' in text
        assert 'trigger_trust="NONE"' in text

    def test_pattern_label_in_output(
        self, mc: MetricsCollector
    ) -> None:
        mc.record_decision(
            "BLOCK", "exec", "NONE",
            matched_patterns=["pattern:ignore_previous_instructions"],
        )
        text = mc.prometheus_text()
        assert "pattern:ignore_previous_instructions" in text
        assert "shieldflow_blocked_patterns_total" in text

    def test_empty_metrics_still_valid(
        self, mc: MetricsCollector
    ) -> None:
        text = mc.prometheus_text()
        # Should still contain the metric families even when empty
        assert "# HELP" in text
        assert "# TYPE" in text
        # No data lines for empty counters (correct behaviour — no 0 labels)
        lines = [
            ln for ln in text.splitlines()
            if ln and not ln.startswith("#") and not ln.strip() == ""
        ]
        assert all(ln.startswith("shieldflow_requests_total") for ln in lines)

    def test_no_line_exceeds_prometheus_limits(
        self, mc: MetricsCollector
    ) -> None:
        mc.record_decision(
            "BLOCK",
            "exec",
            "NONE",
            matched_patterns=["pattern:authority_admin_please"],
            normalisation_flags=["base64_injection"],
        )
        for line in mc.prometheus_text().splitlines():
            assert len(line) < 500, f"Suspiciously long line: {line!r}"


# ─── Label escaping ────────────────────────────────────────────────────────────


class TestLabelEscaping:
    def test_backslash_escaped(self) -> None:
        assert _escape_label("a\\b") == "a\\\\b"

    def test_double_quote_escaped(self) -> None:
        assert _escape_label('a"b') == 'a\\"b'

    def test_newline_escaped(self) -> None:
        assert _escape_label("a\nb") == "a\\nb"

    def test_plain_value_unchanged(self) -> None:
        assert _escape_label("pattern:ignore_previous") == (
            "pattern:ignore_previous"
        )


# ─── Thread safety ─────────────────────────────────────────────────────────────


class TestThreadSafety:
    def test_concurrent_record_request(
        self, mc: MetricsCollector
    ) -> None:
        """1000 concurrent increments must yield exactly 1000."""
        threads = [
            threading.Thread(target=mc.record_request) for _ in range(1000)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert mc.snapshot()["requests_total"] == 1000

    def test_concurrent_record_decision(
        self, mc: MetricsCollector
    ) -> None:
        """500 BLOCK + 500 ALLOW concurrent increments."""

        def block() -> None:
            mc.record_decision("BLOCK", "exec", "NONE")

        def allow() -> None:
            mc.record_decision("ALLOW", "file.read", "USER")

        threads = (
            [threading.Thread(target=block) for _ in range(500)]
            + [threading.Thread(target=allow) for _ in range(500)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snap = mc.snapshot()
        assert snap["decisions"]["block_total"] == 500
        assert snap["decisions"]["allow_total"] == 500


# ─── Endpoints ─────────────────────────────────────────────────────────────────


class TestMetricsEndpoints:
    """Integration tests for /metrics and /metrics/json endpoints."""

    def _make_app(
        self, mc: MetricsCollector
    ) -> Any:
        cfg = open_config()
        return create_app(cfg, audit=AuditLogger(path=None), metrics=mc)

    @pytest.mark.asyncio
    async def test_metrics_endpoint_returns_200(
        self, mc: MetricsCollector
    ) -> None:
        app = self._make_app(mc)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/metrics")
        assert resp.status_code == 200
        assert "shieldflow_requests_total" in resp.text

    @pytest.mark.asyncio
    async def test_metrics_content_type_prometheus(
        self, mc: MetricsCollector
    ) -> None:
        app = self._make_app(mc)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/metrics")
        assert "text/plain" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_metrics_json_returns_snapshot(
        self, mc: MetricsCollector
    ) -> None:
        mc.record_request()
        mc.record_decision("BLOCK", "exec", "NONE")
        app = self._make_app(mc)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.get("/metrics/json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["requests_total"] == 1
        assert data["decisions"]["block_total"] == 1

    @pytest.mark.asyncio
    async def test_proxy_request_increments_counter(
        self, mc: MetricsCollector
    ) -> None:
        """A real proxy request should bump requests_total via _metrics."""
        cfg = open_config()
        app = create_app(cfg, audit=AuditLogger(path=None), metrics=mc)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "id": "test",
            "object": "chat.completion",
            "model": "gpt-4",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "hi"},
                    "finish_reason": "stop",
                }
            ],
        }
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=mock_client
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as ac:
                await ac.post(
                    "/v1/chat/completions",
                    json={
                        "model": "gpt-4",
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                )

        assert mc.snapshot()["requests_total"] == 1
