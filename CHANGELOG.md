# Changelog

All notable changes to ShieldFlow are documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) conventions.

---

## [0.1.0] — 2026-02-19

First public release.  Everything in this release was built from scratch as
the foundational architecture for cryptographic trust boundaries in AI agents.

### Added

#### Core library (`shieldflow.core`)

- **`TrustLevel`** — Six-tier `IntEnum` hierarchy: `NONE → TOOL → AGENT → SYSTEM → USER → OWNER`.
  Levels are comparable with `<`/`>=` and support string parsing via `TrustLevel.from_string()`.

- **`TrustTag`** — Immutable, frozen dataclass carrying trust metadata (level, source, source_id,
  verified_by, and optional elevation provenance).  Once assigned, a tag cannot be mutated —
  this is a core security invariant: *trust is set at ingestion and never escalates through
  processing*.

- **Trust constructors** — Convenience functions `owner_trust()`, `user_trust()`,
  `system_trust()`, and `untrusted()` for creating common trust tags without boilerplate.

- **`ContextBlock`** — A single block of content in a context, pairing text with its
  `TrustTag`, role, block ID, and arbitrary metadata.  Provides `is_instruction` and
  `is_untrusted` property helpers.

- **`SecureContext`** — Trust-aware context builder.  Assembles conversation blocks, injects
  a security preamble, and structurally isolates untrusted content in `[EXTERNAL_DATA …]`
  wrappers when serialised to OpenAI-compatible messages format.

- **`SessionSigner`** — HMAC-SHA256 signing and verification for per-session instruction
  provenance.  Keys are ephemeral (32-byte `os.urandom`), never stored in the context window.
  Signatures carry timestamps; `verify()` enforces a configurable replay-protection window
  (default 5 minutes) using constant-time comparison.

- **`SignedMessage`** / **`VerificationResult`** — Frozen dataclasses for signed content
  and its verification outcome.

- **`create_session_signer()`** — Module-level convenience that creates a `SessionSigner` with
  a fresh random key.

- **`SecureSession`** — High-level session API that ties together signing, context building,
  and validation for one user interaction.  Key methods: `add_instruction()`, `add_system()`,
  `add_data()`, `add_tool_result()`, `to_messages()`, `validate_action()`,
  `validate_actions()`, `new_context()`.

- **`ActionPolicy`** — Frozen dataclass describing the minimum trust level and confirmation
  requirements for a named action type.

- **`ElevationRule`** — Conditional trust elevation from specific verified sources (e.g.,
  allow a DKIM-verified sender to trigger `email.reply`).  Supports allowlists and denylists
  of actions.

- **`DataClass`** — Regex-pattern-based data classification with per-class external-share
  decisions (`allow`, `confirm`, or `block`).

- **`PolicyEngine`** — Evaluates actions against trust requirements and data classification
  policies.  Fails secure: unknown actions default to `OWNER` trust requirement.
  Loads from YAML via `PolicyEngine.from_yaml()`.  Ships with sensible built-in defaults.

- **Default action policies** — 17 built-in policies covering common agent actions:
  read-only operations (any trust), side-effecting operations (user trust), dangerous
  operations (owner trust), and three `never_auto=True` actions requiring per-call
  confirmation (`data.bulk_export`, `credential.read`, `send.new_recipient`).

- **Default data classification** — Three built-in classes: `restricted` (credentials,
  private keys, SSNs — block external share), `internal` (payroll, staff lists — confirm),
  `public` (catch-all — allow).

- **`ToolCall`** — Frozen dataclass representing a tool call from the model (id, name,
  arguments dict).

- **`ValidationResult`** — Frozen dataclass with the full result of a validation: decision
  (`ALLOW`/`BLOCK`/`CONFIRM`), human-readable reason, attributed trigger block, trigger trust
  level, and data classification hit.

- **`ActionValidator`** — Full validation pipeline: (1) attribute the tool call to a context
  block using conservative heuristics, (2) scan untrusted blocks for injection patterns
  related to this action type, (3) evaluate against policy, (4) classify outbound data.

- **Injection pattern library** — 20 compiled regex patterns covering common prompt injection
  techniques: authority impersonation, silent exfiltration, maintenance-mode pretexting,
  GDPR/compliance-baiting, BCC forwarding, and zero-width character evasion.

- **`ShieldFlow`** — Primary entry point class.  Accepts a YAML config path, inline config
  dict, or no config (uses defaults).  Creates sessions via `create_session()` and provides
  top-level `validate_action()` / `validate_actions()`.

#### Proxy server (`shieldflow.proxy`)

- **`ProxyConfig`** — Configuration dataclass for the proxy: upstream URL/key/timeout,
  client API keys, policy path, audit log path, default trust level, host/port.
  Loads from YAML (`ProxyConfig.from_yaml()`) or environment variables (`ProxyConfig.from_env()`).

- **`UpstreamConfig`** — Upstream LLM provider settings (URL, API key, timeout).

- **`AuditLogger`** — Append-only JSONL audit logger.  Writes `request`, `blocked`,
  `response`, and `auth_failure` events.  Falls back to stderr when no path is configured
  (container-friendly).  Line-buffered for immediate flush.

- **`create_app()`** — Factory that builds a FastAPI application implementing an
  OpenAI-compatible proxy.  Handles:
  - Bearer token authentication (skipped when no `api_keys` configured)
  - Role-to-trust mapping (`system→SYSTEM`, `user→USER`, `assistant→AGENT`, `tool→TOOL`)
  - Trust-preamble injection and untrusted-content wrapping
  - Upstream forwarding via `httpx.AsyncClient`
  - Tool-call validation: blocked calls are removed and replaced with inline explanations
  - Response headers: `X-ShieldFlow-Blocked`, `X-ShieldFlow-Trust`, `X-ShieldFlow-Request-ID`
  - Graceful pass-through of non-200 upstream responses

- **`/v1/chat/completions`** — OpenAI-compatible endpoint.

- **`/health`** — Liveness check endpoint returning `{"status": "ok"}`.

#### CLI

- **`shieldflow proxy`** — Start the proxy server from the command line.  Accepts
  `--config`, `--host`, `--port`, `--policy`, and `--audit-log` flags.  Falls back to
  environment variables for all options.

#### Documentation

- **`docs/api/REFERENCE.md`** — Full API reference for every public class, method,
  and constant.  Includes parameter tables, return types, code examples, and the complete
  default policy tables.

- **`docs/guides/openclaw.md`** — Step-by-step integration guide for OpenClaw agents:
  context building, tool name mapping, confirmation flows, multi-turn conversations,
  and structured logging.

- **`docs/guides/quickstart.md`** — Five-minute getting-started guide covering install,
  library mode, proxy mode, configuration, and the audit→enforcement progression.

#### Examples

- **`examples/basic_usage.py`** — Walkthrough of the core API: create session, sign
  instruction, add injected web content, validate a legitimate tool call (ALLOW) and an
  injection-triggered call (BLOCK), demonstrate data-classification blocking.

- **`examples/email_agent.py`** — Realistic email agent processing a synthetic inbox of
  6 emails (legitimate, injection attempts, credential leaks).  Shows trust-gated responses,
  blocked exfiltration, data-classification enforcement, and `never_auto` confirmation flow.

- **`examples/proxy_quickstart.py`** — End-to-end proxy demo: starts a mock upstream and
  the ShieldFlow proxy in background threads, sends a request, inspects `X-ShieldFlow-*`
  headers, and reads the JSONL audit log.

- **`examples/shieldflow.yaml`** — Fully annotated example config covering all options:
  upstream, API keys, network binding, audit log, default trust, action policies (with
  `never_auto` and `confirm_if_elevated`), trust elevation rules, and five data-classification
  classes (`restricted`, `internal`, `pii`, `public`).

### Security

- Trust is **immutable after ingestion** — no code path can escalate a `TrustTag` once set.
- The signing key **never enters the context window** — it lives only in the `SessionSigner`
  instance and is ephemeral per session.
- HMAC comparisons use `hmac.compare_digest` (constant-time) to prevent timing attacks.
- Unknown action types **default to `OWNER` trust requirement** — fail-secure by design.
- Zero-width Unicode characters are stripped before injection pattern matching to defeat
  common evasion techniques.
- Injection attribution is **conservative** — when uncertain, the validator attributes a
  tool call to the lowest-trust available source.

### Known limitations (v0.1.0)

- Trust elevation rules are parsed from YAML but the automatic elevation logic (applying
  them at runtime based on source metadata) is not yet wired into the default request flow.
  Elevation can be applied manually by constructing a `TrustTag` with `elevated_from` set.
- The proxy does not yet support streaming responses (`stream: true`).
- No built-in rate limiting or request size enforcement in the proxy.
- The injection pattern library covers common techniques but is not exhaustive — treat it
  as a first layer, not the only defence.

---

[0.1.0]: https://github.com/shieldflow/shieldflow/releases/tag/v0.1.0
