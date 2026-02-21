"""Integration tests for ShieldFlow proxy server.

These tests use httpx.AsyncClient with a test server to verify
end-to-end behavior.

Run with: pytest tests/integration/ -v
"""

import asyncio
import os
import pytest
import sys
import httpx
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


class TestProxyIntegration:
    """Integration tests for the ShieldFlow proxy."""

    @pytest.fixture
    def proxy_url(self):
        """Return the proxy URL from environment or default."""
        return os.environ.get("SHIELDFLOW_TEST_URL", "http://localhost:8080")

    @pytest.fixture
    def test_token(self):
        """Return a test API token."""
        return os.environ.get("SHIELDFLOW_TEST_TOKEN", "test-token-123")

    @pytest.mark.asyncio
    async def test_health_endpoint(self, proxy_url):
        """Test that /health returns 200."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{proxy_url}/health", timeout=5.0)
                assert response.status_code == 200
            except httpx.ConnectError:
                pytest.skip("Proxy server not running")

    @pytest.mark.asyncio
    async def test_health_ready_endpoint(self, proxy_url):
        """Test that /health/ready returns status."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{proxy_url}/health/ready", timeout=5.0)
                assert response.status_code in (200, 503)
            except httpx.ConnectError:
                pytest.skip("Proxy server not running")

    @pytest.mark.asyncio
    async def test_metrics_endpoint(self, proxy_url):
        """Test that /metrics returns Prometheus format."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{proxy_url}/metrics", timeout=5.0)
                assert response.status_code == 200
                assert "text/plain" in response.headers.get("content-type", "")
            except httpx.ConnectError:
                pytest.skip("Proxy server not running")

    @pytest.mark.asyncio
    async def test_dashboard_endpoint(self, proxy_url):
        """Test that /dashboard returns HTML."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{proxy_url}/dashboard", timeout=5.0)
                assert response.status_code == 200
                assert "text/html" in response.headers.get("content-type", "")
            except httpx.ConnectError:
                pytest.skip("Proxy server not running")

    @pytest.mark.asyncio
    async def test_rejects_missing_auth(self, proxy_url):
        """Test that requests without auth are rejected."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{proxy_url}/v1/chat/completions",
                    json={"messages": [{"role": "user", "content": "Hello"}]},
                    timeout=5.0
                )
                assert response.status_code == 401
            except httpx.ConnectError:
                pytest.skip("Proxy server not running")

    @pytest.mark.asyncio
    async def test_accepts_valid_token(self, proxy_url, test_token):
        """Test that requests with valid auth are accepted."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{proxy_url}/v1/chat/completions",
                    headers={"Authorization": f"Bearer {test_token}"},
                    json={
                        "model": "gpt-4",
                        "messages": [{"role": "user", "content": "Hello"}]
                    },
                    timeout=30.0
                )
                # Should not be 401 (auth error)
                # Could be 200, 400, 500, etc depending on upstream
                assert response.status_code != 401
            except httpx.ConnectError:
                pytest.skip("Proxy server not running")

    @pytest.mark.asyncio
    async def test_request_id_propagation(self, proxy_url, test_token):
        """Test that X-ShieldFlow-Request-ID is returned in response."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{proxy_url}/v1/chat/completions",
                    headers={"Authorization": f"Bearer {test_token}"},
                    json={
                        "model": "gpt-4",
                        "messages": [{"role": "user", "content": "Hello"}]
                    },
                    timeout=30.0
                )
                # Check for request ID in headers
                assert "x-shieldflow-request-id" in response.headers
            except httpx.ConnectError:
                pytest.skip("Proxy server not running")

    @pytest.mark.asyncio
    async def test_session_id_validation(self, proxy_url, test_token):
        """Test that invalid session IDs are rejected."""
        async with httpx.AsyncClient() as client:
            try:
                # Valid session ID should work
                response = await client.post(
                    f"{proxy_url}/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {test_token}",
                        "X-ShieldFlow-Session-ID": "valid-session-123"
                    },
                    json={
                        "model": "gpt-4",
                        "messages": [{"role": "user", "content": "Hello"}]
                    },
                    timeout=30.0
                )
                # Should not fail due to session ID
                assert response.status_code != 401
            except httpx.ConnectError:
                pytest.skip("Proxy server not running")
