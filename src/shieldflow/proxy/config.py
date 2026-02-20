"""Proxy configuration loaded from YAML or environment variables.

Example YAML::

    upstream:
      url: https://api.openai.com
      api_key: sk-...
      timeout: 60.0

    api_keys:
      - my-client-token-1
      - my-client-token-2

    policy_path: /etc/shieldflow/policy.yaml
    audit_log_path: /var/log/shieldflow/audit.jsonl

    default_trust: user
    host: 0.0.0.0
    port: 8080

    # Request guardrails (Phase C)
    max_request_body_bytes: 1048576   # 1 MB; 0 = unlimited
    max_messages_per_request: 500     # 0 = unlimited
    rate_limit_rpm: 0                 # requests per minute per key; 0 = disabled
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from shieldflow.core.trust import TrustLevel


@dataclass
class MCPServerPolicy:
    """Trust policy for a specific MCP (Model Context Protocol) server.

    Controls how content from MCP server responses and resource reads
    is trusted within the ShieldFlow security context.

    Attributes:
        server_trust: Trust level assigned to tool-call responses from
            this server.  Verified servers may be granted ``TOOL`` trust;
            unverified servers should remain at ``NONE``.
        resource_trust: Trust level for resource-read content (e.g.
            ``resources/read``).  Defaults to ``NONE`` because resource
            content is externally sourced and may contain injections.
        verified: Whether this server has a registered, signed manifest.
            Unverified servers are always capped at ``NONE`` trust
            regardless of ``server_trust``.
        allowed_tools: Optional allowlist of tool names this server may
            expose.  ``None`` means all tools are permitted.  If set,
            tool calls to names not in the list are blocked.
        label: Human-readable name for audit/dashboard display.

    Example YAML::

        mcp_servers:
          "https://mcp.internal.corp/v1":
            server_trust: tool
            resource_trust: none
            verified: true
            label: "Internal MCP"
          "https://community-mcp.example.com":
            server_trust: none
            resource_trust: none
            verified: false
            allowed_tools:
              - "search"
              - "calculator"
            label: "Community MCP"
    """

    server_trust: TrustLevel = TrustLevel.NONE
    resource_trust: TrustLevel = TrustLevel.NONE
    verified: bool = False
    allowed_tools: list[str] | None = None
    label: str | None = None

    def effective_server_trust(self) -> TrustLevel:
        """Return the effective trust, capped at NONE for unverified servers."""
        if not self.verified:
            return TrustLevel.NONE
        return self.server_trust

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Return True if *tool_name* is permitted by the allowlist.

        Always returns True when ``allowed_tools`` is None (no restriction).
        """
        if self.allowed_tools is None:
            return True
        return tool_name in self.allowed_tools


# Default policy for any MCP server not explicitly configured.
DEFAULT_MCP_POLICY = MCPServerPolicy(
    server_trust=TrustLevel.NONE,
    resource_trust=TrustLevel.NONE,
    verified=False,
)


@dataclass
class TenantConfig:
    """Per-tenant policy and rate-limit overrides.

    Each field defaults to ``None``, meaning *inherit the global
    ``ProxyConfig`` default*.  Only overridden fields are applied.

    Attributes:
        policy_path: Path to a tenant-specific YAML policy file.
            ``None`` → use the global policy.
        rate_limit_rpm: Requests per minute for this tenant.
            ``None`` → use ``ProxyConfig.rate_limit_rpm``.
        default_trust: Trust level assigned to ``user``-role messages
            from this tenant.  ``None`` → use ``ProxyConfig.default_trust``.
        label: Optional human-readable name used in audit log entries.

    Example YAML::

        tenants:
          "sk-tenant-alpha":
            policy_path: /etc/shieldflow/alpha-policy.yaml
            rate_limit_rpm: 60
            default_trust: user
            label: "Tenant Alpha"
          "sk-tenant-beta":
            rate_limit_rpm: 10
            label: "Tenant Beta"
    """

    policy_path: str | None = None
    rate_limit_rpm: int | None = None
    default_trust: TrustLevel | None = None
    label: str | None = None


@dataclass
class UpstreamConfig:
    """Configuration for the upstream LLM provider."""

    url: str = "https://api.openai.com"
    api_key: str = ""
    timeout: float = 60.0


@dataclass
class ProxyConfig:
    """Full proxy server configuration.

    Attributes:
        upstream: Upstream LLM provider settings.
        api_keys: Accepted Bearer tokens for proxy authentication.
            An empty list disables authentication (development only).
        policy_path: Path to a YAML policy file. Uses default policies if None.
        audit_log_path: Path to the audit log file (JSONL).
            Writes to stderr if None.
        default_trust: Trust level assigned to authenticated requests.
        host: Bind address for the proxy server.
        port: Bind port for the proxy server.
    """

    upstream: UpstreamConfig = field(default_factory=UpstreamConfig)
    api_keys: list[str] = field(default_factory=list)
    policy_path: str | None = None
    audit_log_path: str | None = None
    default_trust: TrustLevel = TrustLevel.USER
    host: str = "0.0.0.0"
    port: int = 8080

    # ── MCP server trust policies ────────────────────────────────────── #
    mcp_servers: dict[str, MCPServerPolicy] = field(default_factory=dict)
    """Per-MCP-server trust policies, keyed by server URL or name.

    Servers not listed here receive :data:`DEFAULT_MCP_POLICY` (all NONE
    trust, unverified).  See :class:`MCPServerPolicy` for field details.
    """

    # ── Multi-tenant overrides ────────────────────────────────────────── #
    tenants: dict[str, TenantConfig] = field(default_factory=dict)
    """Per-tenant configuration overrides, keyed by Bearer token.

    Each key is an API token string (same values as in ``api_keys``).
    The matching :class:`TenantConfig` supplies policy, rate-limit, and
    trust overrides for requests authenticated with that token.

    Tenants not listed here receive global defaults.  Tokens listed in
    ``api_keys`` but absent from ``tenants`` are valid — they just use
    the global config.

    Example: see :class:`TenantConfig`.
    """

    # ── Request guardrails ────────────────────────────────────────────── #
    max_request_body_bytes: int = 1_048_576
    """Maximum allowed request body size in bytes.  ``0`` disables the check.
    Default: 1 MiB (1 048 576 bytes)."""

    max_messages_per_request: int = 500
    """Maximum number of messages permitted in a single chat/completions
    request.  ``0`` disables the check.  Default: 500."""

    rate_limit_rpm: int = 0
    """Maximum requests per minute per API key (or per IP when auth is
    disabled).  ``0`` disables rate limiting.  Default: 0 (unlimited)."""

    @classmethod
    def from_yaml(cls, path: str) -> ProxyConfig:
        """Load configuration from a YAML file.

        Args:
            path: Path to the YAML configuration file.

        Returns:
            A configured ProxyConfig instance.
        """
        with open(path) as f:
            data = yaml.safe_load(f) or {}

        upstream_data = data.get("upstream", {})
        upstream = UpstreamConfig(
            url=upstream_data.get("url", "https://api.openai.com"),
            api_key=upstream_data.get("api_key", os.environ.get("UPSTREAM_API_KEY", "")),
            timeout=float(upstream_data.get("timeout", 60.0)),
        )

        raw_trust = data.get("default_trust", "user")
        default_trust = TrustLevel.from_string(raw_trust)

        # Parse MCP server policies.
        mcp_servers: dict[str, MCPServerPolicy] = {}
        for srv_key, srv_data in (data.get("mcp_servers") or {}).items():
            raw_srv_trust = srv_data.get("server_trust", "none")
            raw_res_trust = srv_data.get("resource_trust", "none")
            mcp_servers[str(srv_key)] = MCPServerPolicy(
                server_trust=TrustLevel.from_string(raw_srv_trust),
                resource_trust=TrustLevel.from_string(raw_res_trust),
                verified=bool(srv_data.get("verified", False)),
                allowed_tools=srv_data.get("allowed_tools"),
                label=srv_data.get("label"),
            )

        # Parse per-tenant overrides.
        tenants: dict[str, TenantConfig] = {}
        for token_key, t_data in (data.get("tenants") or {}).items():
            raw_t_trust = t_data.get("default_trust")
            tenants[str(token_key)] = TenantConfig(
                policy_path=t_data.get("policy_path"),
                rate_limit_rpm=(
                    int(t_data["rate_limit_rpm"])
                    if t_data.get("rate_limit_rpm") is not None
                    else None
                ),
                default_trust=(
                    TrustLevel.from_string(raw_t_trust) if raw_t_trust else None
                ),
                label=t_data.get("label"),
            )

        return cls(
            upstream=upstream,
            api_keys=data.get("api_keys", []),
            policy_path=data.get("policy_path"),
            audit_log_path=data.get("audit_log_path"),
            default_trust=default_trust,
            host=data.get("host", "0.0.0.0"),
            port=int(data.get("port", 8080)),
            mcp_servers=mcp_servers,
            tenants=tenants,
            max_request_body_bytes=int(data.get("max_request_body_bytes", 1_048_576)),
            max_messages_per_request=int(data.get("max_messages_per_request", 500)),
            rate_limit_rpm=int(data.get("rate_limit_rpm", 0)),
        )

    @classmethod
    def from_env(cls) -> ProxyConfig:
        """Load configuration from environment variables.

        Environment variables:
            UPSTREAM_URL: Upstream provider base URL.
            UPSTREAM_API_KEY: API key for the upstream provider.
            UPSTREAM_TIMEOUT: Request timeout in seconds.
            SHIELDFLOW_API_KEYS: Comma-separated list of accepted Bearer tokens.
            SHIELDFLOW_POLICY_PATH: Path to policy YAML.
            SHIELDFLOW_AUDIT_LOG: Path to audit JSONL log.
            SHIELDFLOW_DEFAULT_TRUST: Default trust level (default: user).
            SHIELDFLOW_HOST: Bind host (default: 0.0.0.0).
            SHIELDFLOW_PORT: Bind port (default: 8080).
            SHIELDFLOW_MAX_BODY_BYTES: Max request body in bytes (default: 1048576).
            SHIELDFLOW_MAX_MESSAGES: Max messages per request (default: 500).
            SHIELDFLOW_RATE_LIMIT_RPM: Requests per minute per key (default: 0 = off).

        Returns:
            A configured ProxyConfig instance.
        """
        raw_keys = os.environ.get("SHIELDFLOW_API_KEYS", "")
        api_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]

        raw_trust = os.environ.get("SHIELDFLOW_DEFAULT_TRUST", "user")
        default_trust = TrustLevel.from_string(raw_trust)

        return cls(
            upstream=UpstreamConfig(
                url=os.environ.get("UPSTREAM_URL", "https://api.openai.com"),
                api_key=os.environ.get("UPSTREAM_API_KEY", ""),
                timeout=float(os.environ.get("UPSTREAM_TIMEOUT", "60.0")),
            ),
            api_keys=api_keys,
            policy_path=os.environ.get("SHIELDFLOW_POLICY_PATH"),
            audit_log_path=os.environ.get("SHIELDFLOW_AUDIT_LOG"),
            default_trust=default_trust,
            host=os.environ.get("SHIELDFLOW_HOST", "0.0.0.0"),
            port=int(os.environ.get("SHIELDFLOW_PORT", "8080")),
            max_request_body_bytes=int(
                os.environ.get("SHIELDFLOW_MAX_BODY_BYTES", "1048576")
            ),
            max_messages_per_request=int(
                os.environ.get("SHIELDFLOW_MAX_MESSAGES", "500")
            ),
            rate_limit_rpm=int(os.environ.get("SHIELDFLOW_RATE_LIMIT_RPM", "0")),
        )


# Provider configuration mapping for auto-detection
_OPENCLAW_PROVIDER_CONFIG = {
    "minimax": {
        "url": "https://api.minimax.io/anthropic",
        "env_key": "MINIMAX_API_KEY",
    },
    "anthropic": {
        "url": "https://api.anthropic.com/",
        "env_key": "ANTHROPIC_API_KEY",
    },
    "openai": {
        "url": "https://api.openai.com",
        "env_key": "OPENAI_API_KEY",
    },
}


def load_openclaw_config(config_path: str | None = None) -> dict | None:
    """Load OpenClaw configuration from openclaw.json.

    Args:
        config_path: Optional path to config file.
                     Defaults to ~/.openclaw/openclaw.json

    Returns:
        Parsed config dict or None if not found.
    """
    if config_path is None:
        config_path = Path.home() / ".openclaw" / "openclaw.json"

    try:
        with open(config_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def get_default_model(config: dict) -> str | None:
    """Extract the default model from OpenClaw config.

    Args:
        config: Parsed OpenClaw config dict

    Returns:
        Model string (e.g., "minimax/MiniMax-M2.5") or None.
    """
    try:
        return config.get("agents", {}).get("defaults", {}).get("model", {}).get("primary")
    except (AttributeError, KeyError):
        return None


def parse_model_provider(model: str) -> tuple[str, str] | None:
    """Parse a model string to extract provider and model ID.

    Args:
        model: Model string (e.g., "minimax/MiniMax-M2.5" or "anthropic/claude-sonnet-4-6")

    Returns:
        Tuple of (provider, model_id) or None if invalid.
    """
    if not model or "/" not in model:
        return None

    parts = model.split("/", 1)
    return parts[0], parts[1]


def get_provider_config(provider: str) -> dict | None:
    """Get provider configuration (URL and env var for API key).

    Args:
        provider: Provider name (e.g., "minimax", "anthropic", "openai")

    Returns:
        Provider config dict or None if unknown provider.
    """
    return _OPENCLAW_PROVIDER_CONFIG.get(provider)


def detect_upstream_from_openclaw() -> UpstreamConfig | None:
    """Auto-detect upstream LLM configuration from OpenClaw.

    Reads ~/.openclaw/openclaw.json, extracts the default model,
    maps it to provider settings, and returns an UpstreamConfig.

    Returns:
        UpstreamConfig with detected settings, or None if detection fails.
    """
    # Load OpenClaw config
    config = load_openclaw_config()
    if not config:
        return None

    # Get default model
    model = get_default_model(config)
    if not model:
        return None

    # Parse provider from model
    provider_info = parse_model_provider(model)
    if not provider_info:
        return None

    provider, model_id = provider_info

    # Get provider config
    provider_config = get_provider_config(provider)
    if not provider_config:
        return None

    # Get API key from environment
    api_key = os.environ.get(provider_config["env_key"])
    if not api_key:
        return None

    return UpstreamConfig(
        url=provider_config["url"],
        api_key=api_key,
    )
