# MCP Trust Policy Specification

**Version:** 1.0
**Status:** Active
**Applies to:** ShieldFlow ≥ 0.2.0

## 1. Overview

The Model Context Protocol (MCP) allows AI agents to call tools and read
resources from external servers.  Each MCP server is an independent trust
boundary — a compromised or malicious server can inject content designed
to manipulate the model into executing harmful actions.

This document formalises how ShieldFlow assigns trust levels to content
originating from MCP servers, and how operators configure per-server
policies.

## 2. Trust Model

### 2.1 Two Content Types

MCP servers produce two distinct content types with different trust
semantics:

| Content type | MCP operation | Trust rationale |
|---|---|---|
| **Tool responses** | `tools/call` | Server-generated; trust depends on server verification |
| **Resource content** | `resources/read` | Externally sourced (web pages, files, databases); always low trust |

### 2.2 Trust Assignment Rules

```
┌──────────────────────┐
│   MCP Server         │
│   verified: true     │──── tool response ───▶  server_trust (TOOL)
│   manifest signed    │──── resource read ──▶  resource_trust (NONE)
└──────────────────────┘

┌──────────────────────┐
│   MCP Server         │
│   verified: false    │──── tool response ───▶  NONE (capped)
│   no manifest        │──── resource read ──▶  NONE
└──────────────────────┘
```

**Key invariant:** Unverified servers are **always capped at NONE trust**
regardless of the configured `server_trust` value.  This prevents
privilege escalation via misconfiguration.

### 2.3 Resource Content Is Always Untrusted

Resource content passes *through* the MCP server but originates from
external sources (databases, web APIs, file systems).  Even a verified
server cannot vouch for the safety of resource content.

The default `resource_trust` is `NONE`.  Operators **should not** raise
this above `NONE` unless they control both the server and the data source.

## 3. Configuration

### 3.1 YAML Format

```yaml
mcp_servers:
  "https://mcp.internal.corp/v1":
    server_trust: tool          # TOOL for verified internal server
    resource_trust: none        # resource content is always untrusted
    verified: true              # has a signed manifest
    label: "Internal MCP"

  "https://community.example.com/mcp":
    server_trust: none          # untrusted community server
    resource_trust: none
    verified: false
    allowed_tools:              # restrict which tools may be called
      - "search"
      - "calculator"
    label: "Community Search"
```

### 3.2 Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `server_trust` | TrustLevel | `NONE` | Trust for `tools/call` responses |
| `resource_trust` | TrustLevel | `NONE` | Trust for `resources/read` content |
| `verified` | bool | `false` | Whether server has signed manifest |
| `allowed_tools` | list[str] \| null | `null` (all) | Tool name allowlist |
| `label` | str \| null | `null` | Human-readable name |

### 3.3 Default Policy

Any MCP server not explicitly listed receives `DEFAULT_MCP_POLICY`:

```python
MCPServerPolicy(
    server_trust=TrustLevel.NONE,
    resource_trust=TrustLevel.NONE,
    verified=False,
)
```

This is **secure by default** — unknown servers get zero trust.

## 4. Enforcement

### 4.1 Context Tagging

When MCP content enters the `SecureContext`:

- **Tool responses** → `ctx.add_mcp_tool_result(content, tool_name, server_url, server_trust=policy.effective_server_trust())`
- **Resource reads** → `ctx.add_mcp_resource(content, resource_uri, server_url, resource_trust=policy.resource_trust)`

The `effective_server_trust()` method enforces the verification cap:

```python
def effective_server_trust(self) -> TrustLevel:
    if not self.verified:
        return TrustLevel.NONE  # always capped
    return self.server_trust
```

### 4.2 Tool Allowlisting

If `allowed_tools` is set, any `tools/call` to a name not in the list
is blocked before the request reaches the upstream MCP server.

```python
policy.is_tool_allowed("search")      # True
policy.is_tool_allowed("exec")        # False → block
```

### 4.3 Provenance in Audit Log

MCP content blocks carry provenance metadata:

```json
{
  "trust": {"level": "NONE", "source": "mcp:https://community.example.com/mcp:search"},
  "metadata": {"mcp_server": "https://community.example.com/mcp", "tool_name": "search"}
}
```

This enables operators to trace blocked actions back to the specific
MCP server and tool that produced the triggering content.

## 5. Security Considerations

### 5.1 Server Spoofing

An attacker who controls DNS or the network path can redirect MCP
requests to a malicious server.  Mitigations:

- **TLS verification** — always connect to MCP servers over HTTPS
- **Manifest pinning** — verified servers have signed manifests;
  compare the manifest hash on each connection
- **`verified: true`** only for servers you control or have audited

### 5.2 Injection via Resource Content

The most common MCP attack vector is injecting instructions into
resource content (e.g., a web page read via `resources/read`).
ShieldFlow's existing injection detection + trust-based blocking
handles this: resource content is tagged `NONE`, so any tool calls
it triggers are blocked by the action policy.

### 5.3 Tool Name Collisions

If two MCP servers expose a tool with the same name, the `allowed_tools`
allowlist prevents one server's policy from applying to another's.
Configure `allowed_tools` for each server to avoid collisions.

## 6. Migration Guide

### From default TOOL trust (pre-0.2.0)

Before this policy, all MCP content fell through to the generic
`add_tool_result()` path and received `TOOL` trust.  After migration:

1. All MCP content defaults to `NONE` trust (more restrictive)
2. To restore `TOOL` trust for specific servers, add them to
   `mcp_servers` with `verified: true` and `server_trust: tool`
3. Test with your MCP servers to confirm expected behavior
