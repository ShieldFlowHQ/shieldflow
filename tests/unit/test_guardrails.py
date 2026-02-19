"""Integration tests for Phase C proxy request guardrails.

Verifies that the three guardrail checks work correctly end-to-end
through the FastAPI proxy:

1. Body-size limit  (HTTP 413) — enforced via Content-Length header
2. Message-count limit (HTTP 422) — enforced after body parsing
3. Rate limiting (HTTP 429) — per-key sliding-window via RateLimiter

Also verifies that defaults are sane (no guardrails by default when
limits are set to 0) and that config fields round-trip through
from_yaml / from_env correctly.
"""

from __future__ import annotations

import os
import textwrap
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from shieldflow.proxy.anomaly import AnomalyMonitor
from shieldflow.proxy.audit import AuditLogger
from shieldflow.proxy.config import ProxyConfig, UpstreamConfig
from shieldflow.proxy.server import create_app

# ─── Fixtures ──────────────────────────────────────────────────────────────────


VALID_TOKEN = "test-bearer-token"


def _make_config(**overrides: Any) -> ProxyConfig:
    """Return a ProxyConfig wired for testing."""
    return ProxyConfig(
        api_keys=[VALID_TOKEN],
        upstream=UpstreamConfig(url="http://upstream.test", api_key="up-key"),
        **overrides,
    )


def _make_app(config: ProxyConfig) -> Any:
    """Return a FastAPI app with mocked audit/anomaly."""
    return create_app(config, audit=AuditLogger(None), anomaly=AnomalyMonitor())


def _upstream_mock(status_code: int = 200, body: dict | None = None) -> MagicMock:
    """Return a mock that simulates an upstream response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body or {"model": "gpt-4", "choices": []}
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=None)
    mock.post = AsyncMock(return_value=resp)
    return mock


def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {VALID_TOKEN}"}


def _make_messages(n: int) -> list[dict[str, str]]:
    return [{"role": "user", "content": f"msg {i}"} for i in range(n)]


# ─── Config field defaults ─────────────────────────────────────────────────────


class TestConfigDefaults:
    def test_default_max_body_bytes(self) -> None:
        cfg = ProxyConfig()
        assert cfg.max_request_body_bytes == 1_048_576

    def test_default_max_messages(self) -> None:
        cfg = ProxyConfig()
        assert cfg.max_messages_per_request == 500

    def test_default_rate_limit_rpm(self) -> None:
        cfg = ProxyConfig()
        assert cfg.rate_limit_rpm == 0

    def test_zero_disables_body_limit(self) -> None:
        cfg = ProxyConfig(max_request_body_bytes=0)
        assert cfg.max_request_body_bytes == 0

    def test_zero_disables_message_limit(self) -> None:
        cfg = ProxyConfig(max_messages_per_request=0)
        assert cfg.max_messages_per_request == 0

    def test_zero_disables_rate_limit(self) -> None:
        cfg = ProxyConfig(rate_limit_rpm=0)
        assert cfg.rate_limit_rpm == 0


class TestConfigFromYaml:
    def test_guardrail_fields_load_from_yaml(self, tmp_path: Any) -> None:
        yaml_content = textwrap.dedent("""\
            upstream:
              url: https://api.openai.com
              api_key: sk-test
            max_request_body_bytes: 512000
            max_messages_per_request: 100
            rate_limit_rpm: 30
        """)
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml_content)
        cfg = ProxyConfig.from_yaml(str(cfg_file))
        assert cfg.max_request_body_bytes == 512_000
        assert cfg.max_messages_per_request == 100
        assert cfg.rate_limit_rpm == 30

    def test_guardrail_fields_default_in_yaml(self, tmp_path: Any) -> None:
        yaml_content = "upstream:\n  url: https://api.openai.com\n  api_key: sk\n"
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml_content)
        cfg = ProxyConfig.from_yaml(str(cfg_file))
        assert cfg.max_request_body_bytes == 1_048_576
        assert cfg.max_messages_per_request == 500
        assert cfg.rate_limit_rpm == 0


class TestConfigFromEnv:
    def test_guardrail_env_vars(self) -> None:
        env = {
            "UPSTREAM_API_KEY": "sk-test",
            "SHIELDFLOW_MAX_BODY_BYTES": "65536",
            "SHIELDFLOW_MAX_MESSAGES": "50",
            "SHIELDFLOW_RATE_LIMIT_RPM": "10",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = ProxyConfig.from_env()
        assert cfg.max_request_body_bytes == 65_536
        assert cfg.max_messages_per_request == 50
        assert cfg.rate_limit_rpm == 10

    def test_guardrail_env_defaults(self) -> None:
        # Unset the guardrail env vars so we get defaults
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k not in (
                "SHIELDFLOW_MAX_BODY_BYTES",
                "SHIELDFLOW_MAX_MESSAGES",
                "SHIELDFLOW_RATE_LIMIT_RPM",
            )
        }
        with patch.dict(os.environ, clean_env, clear=True):
            cfg = ProxyConfig.from_env()
        assert cfg.max_request_body_bytes == 1_048_576
        assert cfg.max_messages_per_request == 500
        assert cfg.rate_limit_rpm == 0


# ─── Body-size limit (HTTP 413) ────────────────────────────────────────────────


class TestBodySizeGuardrail:
    @pytest.mark.asyncio
    async def test_content_length_over_limit_returns_413(self) -> None:
        """Content-Length header exceeding limit → HTTP 413 before body read."""
        config = _make_config(max_request_body_bytes=100)
        app = _make_app(config)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                content=b'{"model":"gpt-4","messages":[]}',
                headers={
                    **_auth_headers(),
                    "Content-Type": "application/json",
                    "Content-Length": "999",  # fake large CL
                },
            )
        assert resp.status_code == 413
        assert "bytes" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_content_length_within_limit_is_ok(self) -> None:
        """Content-Length within limit passes through (upstream mock returns 200)."""
        config = _make_config(max_request_body_bytes=1_048_576)
        app = _make_app(config)

        with patch(
            "shieldflow.proxy.server.httpx.AsyncClient", return_value=_upstream_mock()
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                    headers=_auth_headers(),
                )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_body_limit_zero_skips_check(self) -> None:
        """max_request_body_bytes=0 disables the check; even a fake huge CL passes."""
        config = _make_config(max_request_body_bytes=0)
        app = _make_app(config)

        with patch(
            "shieldflow.proxy.server.httpx.AsyncClient", return_value=_upstream_mock()
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/v1/chat/completions",
                    content=b'{"model":"gpt-4","messages":[]}',
                    headers={
                        **_auth_headers(),
                        "Content-Type": "application/json",
                        "Content-Length": "99999999",
                    },
                )
        assert resp.status_code == 200


# ─── Message-count limit (HTTP 422) ────────────────────────────────────────────


class TestMessageCountGuardrail:
    @pytest.mark.asyncio
    async def test_message_count_over_limit_returns_422(self) -> None:
        config = _make_config(max_messages_per_request=5)
        app = _make_app(config)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4", "messages": _make_messages(6)},
                headers=_auth_headers(),
            )
        assert resp.status_code == 422
        assert "messages" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_message_count_at_limit_is_ok(self) -> None:
        config = _make_config(max_messages_per_request=5)
        app = _make_app(config)

        with patch(
            "shieldflow.proxy.server.httpx.AsyncClient", return_value=_upstream_mock()
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": _make_messages(5)},
                    headers=_auth_headers(),
                )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_message_count_zero_disables_check(self) -> None:
        config = _make_config(max_messages_per_request=0)
        app = _make_app(config)

        with patch(
            "shieldflow.proxy.server.httpx.AsyncClient", return_value=_upstream_mock()
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": _make_messages(1000)},
                    headers=_auth_headers(),
                )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_empty_messages_allowed(self) -> None:
        config = _make_config(max_messages_per_request=5)
        app = _make_app(config)

        with patch(
            "shieldflow.proxy.server.httpx.AsyncClient", return_value=_upstream_mock()
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                    headers=_auth_headers(),
                )
        assert resp.status_code == 200


# ─── Rate limiting (HTTP 429) ──────────────────────────────────────────────────


class TestRateLimitGuardrail:
    @pytest.mark.asyncio
    async def test_rate_limit_blocks_after_rpm_exceeded(self) -> None:
        config = _make_config(rate_limit_rpm=2)
        app = _make_app(config)

        with patch(
            "shieldflow.proxy.server.httpx.AsyncClient", return_value=_upstream_mock()
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                headers = _auth_headers()
                # First 2 requests succeed
                r1 = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                    headers=headers,
                )
                r2 = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                    headers=headers,
                )
                # 3rd request hits the limit
                r3 = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                    headers=headers,
                )

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 429
        assert "rate limit" in r3.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_rate_limit_zero_never_blocks(self) -> None:
        config = _make_config(rate_limit_rpm=0)
        app = _make_app(config)

        with patch(
            "shieldflow.proxy.server.httpx.AsyncClient", return_value=_upstream_mock()
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                for _ in range(20):
                    resp = await client.post(
                        "/v1/chat/completions",
                        json={"model": "gpt-4", "messages": []},
                        headers=_auth_headers(),
                    )
                    assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_rate_limit_per_key_independent(self) -> None:
        """Different API keys have independent rate limit buckets."""
        config = ProxyConfig(
            api_keys=["token-a", "token-b"],
            upstream=UpstreamConfig(url="http://up.test", api_key="up-key"),
            rate_limit_rpm=1,
        )
        app = _make_app(config)

        with patch(
            "shieldflow.proxy.server.httpx.AsyncClient", return_value=_upstream_mock()
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                # First request for each key succeeds
                ra1 = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                    headers={"Authorization": "Bearer token-a"},
                )
                rb1 = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                    headers={"Authorization": "Bearer token-b"},
                )
                # Second request for key-a is blocked; key-b bucket is separate
                ra2 = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                    headers={"Authorization": "Bearer token-a"},
                )

        assert ra1.status_code == 200
        assert rb1.status_code == 200
        assert ra2.status_code == 429

    @pytest.mark.asyncio
    async def test_open_mode_rate_limit_uses_ip(self) -> None:
        """In open mode (no api_keys), rate limit falls back to client IP."""
        config = ProxyConfig(
            api_keys=[],  # open mode
            upstream=UpstreamConfig(url="http://up.test", api_key="up-key"),
            rate_limit_rpm=1,
        )
        app = _make_app(config)

        with patch(
            "shieldflow.proxy.server.httpx.AsyncClient", return_value=_upstream_mock()
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                r1 = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                )
                r2 = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                )

        assert r1.status_code == 200
        assert r2.status_code == 429


# ─── Guardrail ordering and combinations ───────────────────────────────────────


class TestGuardrailCombinations:
    @pytest.mark.asyncio
    async def test_body_check_before_message_check(self) -> None:
        """Body-size (413) takes priority over message count (422)."""
        config = _make_config(
            max_request_body_bytes=10,
            max_messages_per_request=5,
        )
        app = _make_app(config)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                content=b'{"model":"gpt-4","messages":[]}',
                headers={
                    **_auth_headers(),
                    "Content-Type": "application/json",
                    "Content-Length": "9999",
                },
            )
        assert resp.status_code == 413

    @pytest.mark.asyncio
    async def test_all_guardrails_disabled_is_passthrough(self) -> None:
        config = _make_config(
            max_request_body_bytes=0,
            max_messages_per_request=0,
            rate_limit_rpm=0,
        )
        app = _make_app(config)

        with patch(
            "shieldflow.proxy.server.httpx.AsyncClient", return_value=_upstream_mock()
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": _make_messages(1000)},
                    headers=_auth_headers(),
                )
        assert resp.status_code == 200
