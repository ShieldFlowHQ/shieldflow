"""Tests for production health/readiness endpoints (Phase C items 4+5).

Covers all three endpoints:
  GET /health          — liveness probe (always 200)
  GET /health/ready    — readiness probe (200 or 503)
  GET /health/detailed — detailed status with uptime, config, metrics, anomaly
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from shieldflow.proxy.anomaly import AnomalyMonitor
from shieldflow.proxy.audit import AuditLogger
from shieldflow.proxy.config import ProxyConfig, TenantConfig, UpstreamConfig
from shieldflow.proxy.server import create_app

# ─── Helpers ───────────────────────────────────────────────────────────────────


def _make_app(config: ProxyConfig) -> Any:
    return create_app(config, audit=AuditLogger(None), anomaly=AnomalyMonitor())


def _full_config(**overrides: Any) -> ProxyConfig:
    return ProxyConfig(
        api_keys=["test-key"],
        upstream=UpstreamConfig(
            url="https://api.openai.com",
            api_key="sk-test",
        ),
        **overrides,
    )


# ─── GET /health ───────────────────────────────────────────────────────────────


class TestLivenessEndpoint:
    @pytest.mark.asyncio
    async def test_health_returns_200(self) -> None:
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.get("/health")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_health_status_ok(self) -> None:
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            data = (await c.get("/health")).json()
        assert data["status"] == "ok"
        assert data["service"] == "shieldflow-proxy"

    @pytest.mark.asyncio
    async def test_health_includes_version(self) -> None:
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            data = (await c.get("/health")).json()
        assert "version" in data
        assert data["version"]  # non-empty string

    @pytest.mark.asyncio
    async def test_health_always_200_even_without_api_keys(self) -> None:
        """Liveness must return 200 even in open/dev mode."""
        config = ProxyConfig(
            api_keys=[],
            upstream=UpstreamConfig(url="https://api.openai.com", api_key="sk"),
        )
        app = _make_app(config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.get("/health")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_health_always_200_without_upstream_key(self) -> None:
        """Liveness does not gate on configuration — that is readiness's job."""
        config = ProxyConfig(
            api_keys=["key"],
            upstream=UpstreamConfig(url="https://api.openai.com", api_key=""),
        )
        app = _make_app(config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.get("/health")
        assert resp.status_code == 200


# ─── GET /health/ready ─────────────────────────────────────────────────────────


class TestReadinessEndpoint:
    @pytest.mark.asyncio
    async def test_ready_200_when_fully_configured(self) -> None:
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.get("/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"

    @pytest.mark.asyncio
    async def test_ready_checks_dict_present(self) -> None:
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            data = (await c.get("/health/ready")).json()
        assert "checks" in data
        assert "upstream_url" in data["checks"]
        assert "upstream_key" in data["checks"]
        assert "auth" in data["checks"]
        assert "policy" in data["checks"]

    @pytest.mark.asyncio
    async def test_ready_503_when_upstream_url_missing(self) -> None:
        config = ProxyConfig(
            api_keys=["key"],
            upstream=UpstreamConfig(url="", api_key="sk"),
        )
        app = _make_app(config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.get("/health/ready")
        assert resp.status_code == 503
        data = resp.json()
        assert data["status"] == "not_ready"
        assert "upstream_url" in data["failures"]

    @pytest.mark.asyncio
    async def test_ready_503_when_upstream_api_key_missing(self) -> None:
        config = ProxyConfig(
            api_keys=["key"],
            upstream=UpstreamConfig(url="https://api.openai.com", api_key=""),
        )
        app = _make_app(config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.get("/health/ready")
        assert resp.status_code == 503
        data = resp.json()
        assert "upstream_key" in data["failures"]

    @pytest.mark.asyncio
    async def test_ready_200_in_open_mode(self) -> None:
        """Open mode (no api_keys) is a valid dev configuration."""
        config = ProxyConfig(
            api_keys=[],
            upstream=UpstreamConfig(url="https://api.openai.com", api_key="sk"),
        )
        app = _make_app(config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.get("/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["auth"] == "open_mode"

    @pytest.mark.asyncio
    async def test_ready_lists_multiple_failures(self) -> None:
        config = ProxyConfig(
            api_keys=["key"],
            upstream=UpstreamConfig(url="", api_key=""),
        )
        app = _make_app(config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.get("/health/ready")
        assert resp.status_code == 503
        failures = resp.json()["failures"]
        assert "upstream_url" in failures
        assert "upstream_key" in failures

    @pytest.mark.asyncio
    async def test_ready_policy_always_ok(self) -> None:
        """Policy engine is always loaded in create_app(); check is always ok."""
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            data = (await c.get("/health/ready")).json()
        assert data["checks"]["policy"] == "ok"


# ─── GET /health/detailed ──────────────────────────────────────────────────────


class TestDetailedEndpoint:
    @pytest.mark.asyncio
    async def test_detailed_returns_200(self) -> None:
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.get("/health/detailed")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_detailed_status_ok(self) -> None:
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            data = (await c.get("/health/detailed")).json()
        assert data["status"] == "ok"
        assert data["service"] == "shieldflow-proxy"
        assert "version" in data

    @pytest.mark.asyncio
    async def test_detailed_uptime_is_positive(self) -> None:
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            data = (await c.get("/health/detailed")).json()
        assert data["uptime_seconds"] >= 0.0

    @pytest.mark.asyncio
    async def test_detailed_config_section(self, tmp_path: Any) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("version: '1'\n")
        config = _full_config(
            policy_path=str(policy_file),
            rate_limit_rpm=42,
            tenants={
                "tok-a": TenantConfig(label="A"),
                "tok-b": TenantConfig(label="B"),
            },
        )
        app = _make_app(config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            cfg = (await c.get("/health/detailed")).json()["config"]

        assert cfg["upstream_url"] == "https://api.openai.com"
        assert cfg["policy_path"] == str(policy_file)
        assert cfg["api_keys_count"] == 1
        assert cfg["tenants_count"] == 2
        assert cfg["rate_limit_rpm"] == 42
        assert cfg["streaming_supported"] is True
        assert cfg["anomaly_detection"] is True
        # Upstream API key must not be leaked in the config section
        assert "sk-test" not in str(cfg)

    @pytest.mark.asyncio
    async def test_detailed_metrics_section(self) -> None:
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            data = (await c.get("/health/detailed")).json()
        assert "metrics" in data
        assert "requests_total" in data["metrics"]
        assert "decisions" in data["metrics"]

    @pytest.mark.asyncio
    async def test_detailed_anomaly_section(self) -> None:
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            data = (await c.get("/health/detailed")).json()
        anomaly = data["anomaly"]
        assert "active_sessions" in anomaly
        assert "sessions_at_risk" in anomaly
        assert "total_spikes" in anomaly
        assert isinstance(anomaly["sessions_at_risk"], list)

    @pytest.mark.asyncio
    async def test_detailed_no_secrets_in_response(self) -> None:
        """Upstream API key must not appear in the detailed status."""
        config = ProxyConfig(
            api_keys=["super-secret-token"],
            upstream=UpstreamConfig(
                url="https://api.openai.com",
                api_key="sk-super-secret-upstream",
            ),
        )
        app = _make_app(config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            body = (await c.get("/health/detailed")).text
        assert "super-secret-token" not in body
        assert "sk-super-secret-upstream" not in body

    @pytest.mark.asyncio
    async def test_detailed_default_trust_in_config(self) -> None:
        app = _make_app(_full_config())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            cfg = (await c.get("/health/detailed")).json()["config"]
        assert cfg["default_trust"] in ("USER", "SYSTEM", "OWNER", "AGENT", "TOOL", "NONE")

    @pytest.mark.asyncio
    async def test_detailed_requests_total_increments(self) -> None:
        """After a real proxy request, requests_total should increase."""
        from unittest.mock import AsyncMock, MagicMock, patch

        config = _full_config()
        app = _make_app(config)

        upstream_resp = MagicMock()
        upstream_resp.status_code = 200
        upstream_resp.json.return_value = {"model": "gpt-4", "choices": []}
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=None)
        mock.post = AsyncMock(return_value=upstream_resp)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            before = (await c.get("/health/detailed")).json()["metrics"]["requests_total"]

            with patch("shieldflow.proxy.server.httpx.AsyncClient", return_value=mock):
                await c.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                    headers={"Authorization": "Bearer test-key"},
                )

            after = (await c.get("/health/detailed")).json()["metrics"]["requests_total"]

        assert after == before + 1
