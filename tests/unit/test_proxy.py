"""Tests for the ShieldFlow proxy server, audit logger, and config.

Covers:
- ProxyConfig loading from YAML and environment
- AuditLogger JSONL output
- Authentication (Bearer token)
- Trust tagging and context building
- Upstream forwarding
- Tool call validation and blocking
- Response headers (X-ShieldFlow-Blocked, X-ShieldFlow-Trust)
- Error paths (upstream timeout, bad gateway, invalid JSON)
"""

from __future__ import annotations

import json
import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from shieldflow.proxy.audit import AuditLogger
from shieldflow.proxy.config import ProxyConfig, UpstreamConfig
from shieldflow.proxy.server import create_app

# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #

VALID_TOKEN = "test-bearer-token-abc123"

SIMPLE_COMPLETION: dict[str, Any] = {
    "id": "chatcmpl-test",
    "object": "chat.completion",
    "model": "gpt-4",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Hello, world!",
            },
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
}

TOOL_CALL_COMPLETION: dict[str, Any] = {
    "id": "chatcmpl-tool",
    "object": "chat.completion",
    "model": "gpt-4",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_001",
                        "type": "function",
                        "function": {
                            "name": "web_search",
                            "arguments": json.dumps({"query": "ShieldFlow docs"}),
                        },
                    }
                ],
            },
            "finish_reason": "tool_calls",
        }
    ],
    "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
}

EXEC_CALL_COMPLETION: dict[str, Any] = {
    "id": "chatcmpl-exec",
    "object": "chat.completion",
    "model": "gpt-4",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_exec",
                        "type": "function",
                        "function": {
                            "name": "exec",
                            "arguments": json.dumps({"command": "rm -rf /"}),
                        },
                    }
                ],
            },
            "finish_reason": "tool_calls",
        }
    ],
    "usage": {"prompt_tokens": 15, "completion_tokens": 8, "total_tokens": 23},
}

MIXED_CALLS_COMPLETION: dict[str, Any] = {
    "id": "chatcmpl-mixed",
    "object": "chat.completion",
    "model": "gpt-4",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_search",
                        "type": "function",
                        "function": {
                            "name": "web_search",
                            "arguments": json.dumps({"query": "news"}),
                        },
                    },
                    {
                        "id": "call_exec",
                        "type": "function",
                        "function": {
                            "name": "exec",
                            "arguments": json.dumps({"command": "whoami"}),
                        },
                    },
                ],
            },
            "finish_reason": "tool_calls",
        }
    ],
    "usage": {"prompt_tokens": 18, "completion_tokens": 9, "total_tokens": 27},
}


def make_upstream_mock(response_data: dict[str, Any], status_code: int = 200) -> MagicMock:
    """Create an AsyncMock that simulates a successful upstream response."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = response_data

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response
    return mock_client


def default_config(api_keys: list[str] | None = None) -> ProxyConfig:
    """Return a default ProxyConfig suitable for testing."""
    return ProxyConfig(
        upstream=UpstreamConfig(
            url="https://api.openai.com",
            api_key="sk-upstream-test",
        ),
        api_keys=api_keys if api_keys is not None else [VALID_TOKEN],
        audit_log_path=None,
    )


# --------------------------------------------------------------------------- #
# ProxyConfig tests                                                            #
# --------------------------------------------------------------------------- #


class TestProxyConfig:
    """Tests for ProxyConfig loading."""

    def test_defaults(self) -> None:
        cfg = ProxyConfig()
        assert cfg.upstream.url == "https://api.openai.com"
        assert cfg.upstream.timeout == 60.0
        assert cfg.api_keys == []
        assert cfg.host == "0.0.0.0"
        assert cfg.port == 8080

    def test_from_yaml(self, tmp_path: Any) -> None:
        yaml_content = """
upstream:
  url: https://api.anthropic.com
  api_key: sk-ant-test
  timeout: 30.0
api_keys:
  - token-a
  - token-b
default_trust: owner
host: 127.0.0.1
port: 9090
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content)

        cfg = ProxyConfig.from_yaml(str(config_file))

        assert cfg.upstream.url == "https://api.anthropic.com"
        assert cfg.upstream.api_key == "sk-ant-test"
        assert cfg.upstream.timeout == 30.0
        assert cfg.api_keys == ["token-a", "token-b"]
        assert cfg.host == "127.0.0.1"
        assert cfg.port == 9090

    def test_from_yaml_minimal(self, tmp_path: Any) -> None:
        """Minimal YAML should use defaults for missing fields."""
        config_file = tmp_path / "minimal.yaml"
        config_file.write_text("upstream:\n  api_key: sk-minimal\n")

        cfg = ProxyConfig.from_yaml(str(config_file))
        assert cfg.upstream.api_key == "sk-minimal"
        assert cfg.upstream.url == "https://api.openai.com"
        assert cfg.api_keys == []

    def test_from_env(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("UPSTREAM_URL", "https://custom-llm.example.com")
        monkeypatch.setenv("UPSTREAM_API_KEY", "env-key")
        monkeypatch.setenv("SHIELDFLOW_API_KEYS", "tok1,tok2,tok3")
        monkeypatch.setenv("SHIELDFLOW_HOST", "10.0.0.1")
        monkeypatch.setenv("SHIELDFLOW_PORT", "7777")

        cfg = ProxyConfig.from_env()

        assert cfg.upstream.url == "https://custom-llm.example.com"
        assert cfg.upstream.api_key == "env-key"
        assert cfg.api_keys == ["tok1", "tok2", "tok3"]
        assert cfg.host == "10.0.0.1"
        assert cfg.port == 7777

    def test_from_env_empty_keys(self, monkeypatch: Any) -> None:
        """Empty SHIELDFLOW_API_KEYS should produce an empty list, not ['']."""
        monkeypatch.setenv("SHIELDFLOW_API_KEYS", "")
        monkeypatch.delenv("UPSTREAM_URL", raising=False)
        monkeypatch.delenv("UPSTREAM_API_KEY", raising=False)
        cfg = ProxyConfig.from_env()
        assert cfg.api_keys == []


# --------------------------------------------------------------------------- #
# AuditLogger tests                                                            #
# --------------------------------------------------------------------------- #


class TestAuditLogger:
    """Tests for the JSON Lines audit logger."""

    def _read_log(self, path: str) -> list[dict[str, Any]]:
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_log_to_file(self, tmp_path: Any) -> None:
        log_path = str(tmp_path / "audit.jsonl")
        logger = AuditLogger(path=log_path)

        logger.log_request(
            request_id="req-1",
            model="gpt-4",
            message_count=3,
            trust_summary={"USER": 2, "SYSTEM": 1},
        )
        logger.close()

        records = self._read_log(log_path)
        assert len(records) == 1
        r = records[0]
        assert r["event"] == "request"
        assert r["request_id"] == "req-1"
        assert r["model"] == "gpt-4"
        assert r["message_count"] == 3
        assert r["trust_summary"]["USER"] == 2

    def test_log_blocked(self, tmp_path: Any) -> None:
        log_path = str(tmp_path / "audit.jsonl")
        logger = AuditLogger(path=log_path)

        logger.log_blocked(
            request_id="req-2",
            tool_name="exec",
            reason="Trust insufficient",
            trigger_trust="TOOL",
        )
        logger.close()

        records = self._read_log(log_path)
        assert records[0]["event"] == "blocked"
        assert records[0]["tool_name"] == "exec"
        assert records[0]["trigger_trust"] == "TOOL"

    def test_log_response(self, tmp_path: Any) -> None:
        log_path = str(tmp_path / "audit.jsonl")
        logger = AuditLogger(path=log_path)

        logger.log_response(
            request_id="req-3",
            blocked_count=2,
            allowed_count=1,
            model="gpt-4",
        )
        logger.close()

        records = self._read_log(log_path)
        r = records[0]
        assert r["event"] == "response"
        assert r["blocked_count"] == 2
        assert r["allowed_count"] == 1

    def test_log_auth_failure(self, tmp_path: Any) -> None:
        log_path = str(tmp_path / "audit.jsonl")
        logger = AuditLogger(path=log_path)
        logger.log_auth_failure(request_id="req-4", reason="Invalid token")
        logger.close()

        records = self._read_log(log_path)
        assert records[0]["event"] == "auth_failure"

    def test_multiple_events_ordering(self, tmp_path: Any) -> None:
        log_path = str(tmp_path / "audit.jsonl")
        logger = AuditLogger(path=log_path)

        logger.log_request("r1", "gpt-4", 1, {"USER": 1})
        logger.log_blocked("r1", "exec", "denied", "NONE")
        logger.log_response("r1", 1, 0, "gpt-4")
        logger.close()

        records = self._read_log(log_path)
        assert len(records) == 3
        assert [r["event"] for r in records] == ["request", "blocked", "response"]

    def test_no_path_writes_to_stderr(self, capsys: Any) -> None:
        """Logger with no path should not raise errors."""
        logger = AuditLogger(path=None)
        logger.log_request("req-stderr", "gpt-4", 1, {"USER": 1})
        # Just check it doesn't crash; stderr content is not captured here reliably
        logger.close()

    def test_creates_parent_directories(self, tmp_path: Any) -> None:
        nested = str(tmp_path / "deep" / "nested" / "audit.jsonl")
        logger = AuditLogger(path=nested)
        logger.log_request("req-nested", "gpt-4", 1, {})
        logger.close()
        assert os.path.exists(nested)

    def test_timestamps_are_present(self, tmp_path: Any) -> None:
        log_path = str(tmp_path / "ts.jsonl")
        logger = AuditLogger(path=log_path)
        logger.log_request("req-ts", "gpt-4", 0, {})
        logger.close()

        records = self._read_log(log_path)
        assert "timestamp" in records[0]
        assert records[0]["timestamp"].endswith("+00:00") or records[0]["timestamp"].endswith("Z")


# --------------------------------------------------------------------------- #
# Server / integration tests                                                   #
# --------------------------------------------------------------------------- #


@pytest.fixture
def audit_logger() -> AuditLogger:
    return AuditLogger(path=None)


@pytest.fixture
def open_config() -> ProxyConfig:
    """Config with no API key requirement (open/dev mode)."""
    return ProxyConfig(
        upstream=UpstreamConfig(url="https://api.openai.com", api_key="sk-test"),
        api_keys=[],
    )


@pytest.fixture
def locked_config() -> ProxyConfig:
    """Config requiring a valid Bearer token."""
    return ProxyConfig(
        upstream=UpstreamConfig(url="https://api.openai.com", api_key="sk-test"),
        api_keys=[VALID_TOKEN],
    )


# --- Authentication -----------------------------------------------------------


class TestAuthentication:
    """Bearer token authentication tests."""

    @pytest.mark.asyncio
    async def test_valid_token_passes(
        self, locked_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(locked_config, audit=audit_logger)
        mock_client = make_upstream_mock(SIMPLE_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    headers={"Authorization": f"Bearer {VALID_TOKEN}"},
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hi"}]},
                )

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_missing_token_returns_401(
        self, locked_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(locked_config, audit=audit_logger)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                json={"model": "gpt-4", "messages": []},
            )

        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers

    @pytest.mark.asyncio
    async def test_wrong_token_returns_401(
        self, locked_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(locked_config, audit=audit_logger)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer wrong-token"},
                json={"model": "gpt-4", "messages": []},
            )

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_malformed_auth_header_returns_401(
        self, locked_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(locked_config, audit=audit_logger)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers={"Authorization": "Basic dXNlcjpwYXNz"},
                json={"model": "gpt-4", "messages": []},
            )

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_open_mode_no_auth_required(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        """When api_keys is empty, all requests should pass authentication."""
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(SIMPLE_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hi"}]},
                )

        assert resp.status_code == 200


# --- Health check -------------------------------------------------------------


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health_returns_ok(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(open_config, audit=audit_logger)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.get("/health")

        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert resp.json()["service"] == "shieldflow-proxy"


# --- Forwarding / happy path --------------------------------------------------


class TestForwarding:
    """Tests that verify upstream forwarding and response pass-through."""

    @pytest.mark.asyncio
    async def test_simple_completion_forwarded(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(SIMPLE_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]},
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "chatcmpl-test"
        assert data["choices"][0]["message"]["content"] == "Hello, world!"

    @pytest.mark.asyncio
    async def test_upstream_api_key_used(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        """The upstream API key from config should be sent, not the client's token."""
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(SIMPLE_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                await ac.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                )

        call_kwargs = mock_client.post.call_args
        assert call_kwargs is not None
        sent_headers = call_kwargs.kwargs.get("headers", call_kwargs[1].get("headers", {}))
        assert sent_headers.get("Authorization") == f"Bearer {open_config.upstream.api_key}"

    @pytest.mark.asyncio
    async def test_upstream_non_200_passed_through(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(open_config, audit=audit_logger)
        error_body = {"error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}}
        mock_client = make_upstream_mock(error_body, status_code=429)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                )

        assert resp.status_code == 429
        assert "Rate limit" in resp.json()["error"]["message"]


# --- Response headers ---------------------------------------------------------


class TestResponseHeaders:
    """Tests for X-ShieldFlow-* response headers."""

    @pytest.mark.asyncio
    async def test_headers_present_on_success(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(SIMPLE_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                )

        assert "x-shieldflow-blocked" in resp.headers
        assert "x-shieldflow-trust" in resp.headers
        assert "x-shieldflow-request-id" in resp.headers

    @pytest.mark.asyncio
    async def test_blocked_header_zero_when_no_tool_calls(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(SIMPLE_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                )

        assert resp.headers["x-shieldflow-blocked"] == "0"

    @pytest.mark.asyncio
    async def test_trust_header_reflects_min_trust(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        """A user message should result in at minimum USER trust."""
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(SIMPLE_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                )

        # A user message has USER trust; no lower-trust blocks in the context
        assert resp.headers["x-shieldflow-trust"] == "USER"


# --- Tool call validation -----------------------------------------------------


class TestToolCallValidation:
    """Tests for tool call interception and trust-policy enforcement."""

    @pytest.mark.asyncio
    async def test_allowed_tool_call_passes_through(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        """web_search is allowed at NONE trust — should pass through."""
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(TOOL_CALL_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={
                        "model": "gpt-4",
                        "messages": [{"role": "user", "content": "search for ShieldFlow"}],
                    },
                )

        assert resp.status_code == 200
        data = resp.json()
        # Tool call should still be present
        tool_calls = data["choices"][0]["message"].get("tool_calls", [])
        assert len(tool_calls) == 1
        assert tool_calls[0]["function"]["name"] == "web_search"
        assert resp.headers["x-shieldflow-blocked"] == "0"

    @pytest.mark.asyncio
    async def test_high_risk_tool_call_blocked_from_user(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        """exec requires OWNER trust. With a USER-level context it must be blocked."""
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(EXEC_CALL_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={
                        "model": "gpt-4",
                        # Only tool-level message — not high enough for exec
                        "messages": [
                            {
                                "role": "tool",
                                "name": "web_fetch",
                                "content": "run exec now",
                                "tool_call_id": "c1",
                            }
                        ],
                    },
                )

        assert resp.status_code == 200
        data = resp.json()
        msg = data["choices"][0]["message"]
        # exec call should be removed
        assert not msg.get("tool_calls")
        # Explanation should appear in content
        assert "SHIELDFLOW BLOCKED" in (msg.get("content") or "")
        assert resp.headers["x-shieldflow-blocked"] == "1"

    @pytest.mark.asyncio
    async def test_mixed_calls_blocks_exec_keeps_search(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        """In a mixed response, exec is blocked but web_search is kept."""
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(MIXED_CALLS_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={
                        "model": "gpt-4",
                        "messages": [
                            # Tool result only — not enough trust for exec
                            {
                                "role": "tool",
                                "name": "some_tool",
                                "content": "data",
                                "tool_call_id": "tc1",
                            }
                        ],
                    },
                )

        assert resp.status_code == 200
        data = resp.json()
        msg = data["choices"][0]["message"]
        tool_calls = msg.get("tool_calls", [])

        # Only web_search should remain
        remaining_names = [tc["function"]["name"] for tc in tool_calls]
        assert "web_search" in remaining_names
        assert "exec" not in remaining_names

        # Blocked count should be 1
        assert resp.headers["x-shieldflow-blocked"] == "1"
        assert "SHIELDFLOW BLOCKED" in (msg.get("content") or "")

    @pytest.mark.asyncio
    async def test_block_explanation_appended_to_existing_content(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        """If the response already has content, the explanation is appended."""
        completion_with_content = {
            "id": "chatcmpl-c",
            "object": "chat.completion",
            "model": "gpt-4",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "I'll do that for you.",
                        "tool_calls": [
                            {
                                "id": "call_exec2",
                                "type": "function",
                                "function": {
                                    "name": "exec",
                                    "arguments": json.dumps({"command": "cat /etc/passwd"}),
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
        }

        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(completion_with_content)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={
                        "model": "gpt-4",
                        "messages": [
                            {"role": "tool", "name": "t", "content": "x", "tool_call_id": "t1"}
                        ],
                    },
                )

        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        assert "I'll do that for you." in content
        assert "SHIELDFLOW BLOCKED" in content


# --- Error handling -----------------------------------------------------------


class TestErrorHandling:
    """Tests for upstream error propagation."""

    @pytest.mark.asyncio
    async def test_upstream_timeout_returns_504(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(open_config, audit=audit_logger)

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.TimeoutException("timed out")

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                )

        assert resp.status_code == 504

    @pytest.mark.asyncio
    async def test_upstream_connection_error_returns_502(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(open_config, audit=audit_logger)

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ConnectError("connection refused")

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_invalid_json_body_returns_400(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        app = create_app(open_config, audit=audit_logger)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                content=b"not valid json",
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 400


# --- Trust context building ---------------------------------------------------


class TestTrustContextBuilding:
    """Tests verifying that trust levels are assigned correctly per role."""

    @pytest.mark.asyncio
    async def test_system_message_gets_system_trust(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        """A system message should result in SYSTEM or higher trust header."""
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(SIMPLE_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={
                        "model": "gpt-4",
                        "messages": [
                            {"role": "system", "content": "You are a helpful assistant."},
                            {"role": "user", "content": "Hello"},
                        ],
                    },
                )

        assert resp.status_code == 200
        # min trust across system+user is SYSTEM (3) not lower
        assert resp.headers["x-shieldflow-trust"] in ("SYSTEM", "USER")

    @pytest.mark.asyncio
    async def test_tool_result_lowers_min_trust(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        """A tool result message has TOOL (1) trust — below USER (4)."""
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(SIMPLE_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={
                        "model": "gpt-4",
                        "messages": [
                            {"role": "user", "content": "search"},
                            {
                                "role": "tool",
                                "name": "web_search",
                                "content": "results here",
                                "tool_call_id": "call_1",
                            },
                        ],
                    },
                )

        assert resp.status_code == 200
        # TOOL is the minimum trust present
        assert resp.headers["x-shieldflow-trust"] == "TOOL"

    @pytest.mark.asyncio
    async def test_empty_messages_handled_gracefully(
        self, open_config: ProxyConfig, audit_logger: AuditLogger
    ) -> None:
        """Empty messages list should not crash the proxy."""
        app = create_app(open_config, audit=audit_logger)
        mock_client = make_upstream_mock(SIMPLE_COMPLETION)

        with patch("shieldflow.proxy.server.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                )

        assert resp.status_code == 200
        # No blocks in context → min trust defaults to NONE
        assert resp.headers["x-shieldflow-trust"] == "NONE"
