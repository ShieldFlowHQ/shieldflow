"""FastAPI proxy server for ShieldFlow.

The proxy sits in front of any OpenAI-compatible LLM API and enforces
trust boundaries on every request.

Additional endpoints:
    GET /health         — liveness probe (always 200 while process is alive).
    GET /health/ready   — readiness probe (503 when misconfigured).
    GET /health/detailed — rich status: uptime, config summary, metrics, anomaly.
    GET /metrics        — Prometheus text exposition.
    GET /metrics/json   — JSON metrics + anomaly snapshot.
    GET /dashboard      — security decision triage dashboard.

Core pipeline:

1. **Authentication** — clients must present a valid Bearer token.
2. **Trust tagging** — each message in the conversation is assigned a
   trust level (USER, SYSTEM, AGENT, TOOL, NONE) based on its role.
3. **Upstream forwarding** — the request is forwarded verbatim to the
   configured upstream provider using the *upstream* API key.
4. **Tool call validation** — tool_calls in the response are validated
   against the trust policy. Blocked calls are removed and replaced
   with inline explanations so the model can report the failure.
5. **Streaming support** — ``stream: true`` requests are handled by
   buffering the upstream SSE stream, reconstructing the full completion,
   running the same tool-call validation, then re-emitting a validated
   SSE response to the client.
6. **Audit logging** — every request, block, and response is logged in
   JSONL format for forensic review.

Response headers added by the proxy:
    X-ShieldFlow-Blocked:          Number of tool calls blocked (integer string).
    X-ShieldFlow-Trust:            Minimum trust level present in the context.
    X-ShieldFlow-Request-ID:       UUID for correlating audit log entries.
    X-ShieldFlow-Session-ID:       Echo of caller-supplied session ID (when present).
    X-ShieldFlow-Risk-Score:       Rolling risk score 0.0–1.0 for the session (when session ID
                                   is supplied).
    X-ShieldFlow-Session-At-Risk:  "true" when the session's risk score exceeds the spike threshold.
    X-ShieldFlow-Streamed:         "buffered-validated" on stream=true requests — indicates the
                                   proxy buffered the SSE stream to perform full tool-call
                                   validation before re-emitting to the client.
    X-ShieldFlow-Tenant:           Human-readable tenant label (when TenantConfig.label is set
                                   for the authenticated token).
"""

from __future__ import annotations

import json
import signal
import sys
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from shieldflow.core.context import SecureContext
from shieldflow.core.policy import PolicyEngine
from shieldflow.core.trust import TrustLevel, TrustTag
from shieldflow.core.validator import ActionValidator, ToolCall
from shieldflow.proxy.anomaly import AnomalyMonitor
from shieldflow.proxy.audit import AuditLogger
from shieldflow.proxy.config import ProxyConfig, TenantConfig
from shieldflow.proxy.dashboard import DecisionLog, add_dashboard_routes
from shieldflow.proxy.metrics import MetricsCollector
from shieldflow.proxy.ratelimit import RateLimiter


# Global shutdown event for graceful handling
_shutdown_event: signal.Event | None = None
_shutdown_timeout: float = 30.0  # seconds to wait for in-flight requests


def _create_shutdown_handler(ready_event: signal.Event | None = None):
    """Create a shutdown handler that sets the shutdown event."""
    def shutdown_handler(signum, frame):
        nonlocal _shutdown_event
        if _shutdown_event:
            _shutdown_event.set()
            print(f"\n🚪 Received signal {signum}, initiating graceful shutdown...")
            print(f"   Waiting up to {_shutdown_timeout}s for in-flight requests to complete...")
            if ready_event:
                ready_event.clear()
    return shutdown_handler


def create_app(
    config: ProxyConfig,
    audit: AuditLogger | None = None,
    metrics: MetricsCollector | None = None,
    decision_log: DecisionLog | None = None,
    anomaly: AnomalyMonitor | None = None,
) -> FastAPI:
    """Create and configure the ShieldFlow proxy FastAPI application.

    Args:
        config: Proxy configuration (upstream URL, API keys, policy, etc.).
        audit:  Optional pre-configured AuditLogger. A new one will be
                created from ``config.audit_log_path`` if not provided.

    Returns:
        A fully configured FastAPI application ready to serve.
    """
    app = FastAPI(
        title="ShieldFlow Proxy",
        description=(
            "Trust-boundary proxy for LLM APIs. "
            "Enforces action policies and blocks prompt-injection-triggered tool calls."
        ),
        version="0.1.0",
    )

    _audit = audit or AuditLogger(config.audit_log_path)
    _metrics = metrics or MetricsCollector()
    _decision_log = decision_log or DecisionLog()
    _anomaly = anomaly or AnomalyMonitor()
    _rate_limiter = RateLimiter(rpm=config.rate_limit_rpm)
    _start_time: float = time.monotonic()

    # Load policy engine from file or use defaults
    _policy = PolicyEngine.from_yaml(config.policy_path) if config.policy_path else PolicyEngine()
    _validator = ActionValidator(_policy)

    # Per-tenant caches — populated lazily on first request per token.
    # Keys are Bearer token strings; values are tenant-specific instances.
    # Thread-safety note: asyncio runs on a single event-loop thread so
    # plain dict reads/writes are safe without explicit locks.
    _tenant_validators: dict[str, ActionValidator] = {}
    _tenant_limiters: dict[str, RateLimiter] = {}

    # ------------------------------------------------------------------ #
    # Helper: authentication                                               #
    # ------------------------------------------------------------------ #

    def _authenticate(request: Request) -> str | None:
        """Raise HTTP 401 if the Bearer token is missing or invalid.

        Authentication is skipped entirely when no ``api_keys`` are
        configured (development / local mode).

        Returns:
            The validated Bearer token string, or ``None`` when auth is
            disabled (open mode).  The return value is used as the
            rate-limit key.
        """
        if not config.api_keys:
            return None  # Open mode — no keys configured

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or malformed Authorization header. Expected: Bearer <token>",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[len("Bearer ") :]
        if token not in config.api_keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return token

    # ------------------------------------------------------------------ #
    # Helper: request guardrails                                           #
    # ------------------------------------------------------------------ #

    def _check_guardrails(
        request: Request,
        messages: list[dict[str, Any]],
        rate_key: str | None,
        limiter: RateLimiter | None = None,
    ) -> None:
        """Enforce body-size, message-count, and rate-limit guardrails.

        Must be called **after** the request body has been parsed so the
        actual message list is available.  The Content-Length header is
        also checked as an early fast-path for oversized bodies.

        Args:
            request: The incoming FastAPI ``Request`` object.
            messages: Parsed message list from the request body.
            rate_key: Key for per-key rate limiting (typically the Bearer
                token, or ``None`` to fall back to the client IP).
            limiter: Rate limiter to use.  Defaults to the global
                ``_rate_limiter``; pass a tenant-specific limiter to
                enforce per-tenant RPM overrides.

        Raises:
            :class:`fastapi.HTTPException` 413 — body exceeds
                ``config.max_request_body_bytes``.
            :class:`fastapi.HTTPException` 422 — message count exceeds
                ``config.max_messages_per_request``.
            :class:`fastapi.HTTPException` 429 — rate limit exceeded.
        """
        # 1. Body size — check Content-Length header as fast path.
        if config.max_request_body_bytes > 0:
            cl = request.headers.get("content-length")
            if cl and int(cl) > config.max_request_body_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=(
                        f"Request body exceeds limit of "
                        f"{config.max_request_body_bytes:,} bytes "
                        f"(Content-Length: {int(cl):,} bytes)."
                    ),
                )

        # 2. Message count.
        if config.max_messages_per_request > 0:
            if len(messages) > config.max_messages_per_request:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"Request contains {len(messages)} messages; "
                        f"maximum allowed is {config.max_messages_per_request}."
                    ),
                )

        # 3. Rate limit — use the Bearer token as the key; fall back to
        #    the client IP when auth is disabled (development mode).
        #    Use the tenant-specific limiter if provided.
        rl_key = rate_key or (request.client.host if request.client else "unknown")
        (limiter or _rate_limiter).check(rl_key)

    # ------------------------------------------------------------------ #
    # Helper: tenant resolution                                            #
    # ------------------------------------------------------------------ #

    def _resolve_tenant(
        token: str | None,
    ) -> tuple[ActionValidator, RateLimiter, TrustLevel]:
        """Return the effective (validator, limiter, default_trust) for *token*.

        Looks up the token in ``config.tenants``; if found, applies the
        tenant's overrides on top of global defaults.  Any per-tenant
        field set to ``None`` falls back to the global value.

        Per-tenant :class:`~shieldflow.core.validator.ActionValidator` and
        :class:`~shieldflow.proxy.ratelimit.RateLimiter` instances are
        cached in ``_tenant_validators`` and ``_tenant_limiters`` after
        their first creation and reused for subsequent requests.

        Args:
            token: The validated Bearer token string (from
                :func:`_authenticate`), or ``None`` in open/dev mode.

        Returns:
            A 3-tuple of *(validator, rate_limiter, default_trust)*.
        """
        if not token or token not in config.tenants:
            return _validator, _rate_limiter, config.default_trust

        tenant: TenantConfig = config.tenants[token]

        # Validator — load and cache tenant-specific policy engine.
        if tenant.policy_path is not None:
            if token not in _tenant_validators:
                t_policy = PolicyEngine.from_yaml(tenant.policy_path)
                _tenant_validators[token] = ActionValidator(t_policy)
            t_validator = _tenant_validators[token]
        else:
            t_validator = _validator

        # Rate limiter — create and cache with tenant-specific RPM.
        if token not in _tenant_limiters:
            rpm = (
                tenant.rate_limit_rpm
                if tenant.rate_limit_rpm is not None
                else config.rate_limit_rpm
            )
            _tenant_limiters[token] = RateLimiter(rpm=rpm)
        t_limiter = _tenant_limiters[token]

        # Default trust level for user-role messages.
        t_trust = (
            tenant.default_trust
            if tenant.default_trust is not None
            else config.default_trust
        )

        return t_validator, t_limiter, t_trust

    # ------------------------------------------------------------------ #
    # Helper: context building                                             #
    # ------------------------------------------------------------------ #

    def _build_context(
        messages: list[dict[str, Any]],
        user_trust: TrustLevel = TrustLevel.USER,
    ) -> SecureContext:
        """Build a trust-tagged SecureContext from OpenAI-format messages.

        Role → trust level mapping:
            system    → SYSTEM  (framework-injected instructions)
            user      → USER    (authenticated via Bearer token)
            assistant → AGENT   (prior LLM output; informational)
            tool      → TOOL    (tool result; informational)
            *         → NONE    (unknown source; untrusted)
        """
        ctx = SecureContext()

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content") or ""

            if role == "system":
                ctx.add_system(content)

            elif role == "user":
                ctx.add_instruction(
                    content,
                    trust=TrustTag(
                        level=user_trust,
                        source="user_chat",
                        verified_by="api_auth",
                    ),
                    role="user",
                )

            elif role == "assistant":
                # Prior assistant output is AGENT-level (not fully trusted)
                ctx.add_data(
                    content,
                    source="assistant",
                    trust=TrustLevel.AGENT,
                    role="assistant",
                )

            elif role == "tool":
                ctx.add_tool_result(
                    content,
                    tool_name=msg.get("name", "unknown_tool"),
                    tool_call_id=msg.get("tool_call_id"),
                )

            else:
                # Unknown role → untrusted
                ctx.add_data(content, source=role, trust=TrustLevel.NONE, role=role)

        return ctx

    def _trust_summary(ctx: SecureContext) -> dict[str, int]:
        """Return a count of blocks per trust level name."""
        summary: dict[str, int] = {}
        for block in ctx.blocks:
            name = block.trust.level.name
            summary[name] = summary.get(name, 0) + 1
        return summary

    def _min_trust(ctx: SecureContext) -> TrustLevel:
        """Return the lowest trust level present in the context."""
        levels = [b.trust.level for b in ctx.blocks]
        return min(levels, default=TrustLevel.NONE)

    # ------------------------------------------------------------------ #
    # Helper: tool call validation                                         #
    # ------------------------------------------------------------------ #

    def _validate_tool_calls(
        response_message: dict[str, Any],
        ctx: SecureContext,
        request_id: str,
        session_id: str | None = None,
        validator: ActionValidator | None = None,
    ) -> tuple[dict[str, Any], int, int]:
        """Validate tool_calls from the LLM response.

        Blocked calls are removed from the response and replaced with
        inline explanation text so the model can communicate the failure
        to the user on the next turn.

        Args:
            response_message: The ``message`` object from a response choice.
            ctx: The SecureContext built from the original request.
            request_id: UUID for audit log correlation.
            session_id: Optional caller-supplied session identifier for
                multi-turn anomaly tracking.
            validator: Validator to use.  Defaults to the global
                ``_validator``; pass a tenant-specific one to enforce
                per-tenant policy.

        Returns:
            A tuple of (modified_message, blocked_count, allowed_count).
        """
        tool_calls: list[dict[str, Any]] = response_message.get("tool_calls") or []
        if not tool_calls:
            return response_message, 0, 0

        allowed_calls: list[dict[str, Any]] = []
        blocked_explanations: list[str] = []
        blocked_count = 0

        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name", "unknown")

            try:
                args: dict[str, Any] = json.loads(fn.get("arguments", "{}"))
            except (json.JSONDecodeError, TypeError):
                args = {}

            tool_call = ToolCall(
                id=tc.get("id") or f"call_{uuid.uuid4().hex[:8]}",
                name=name,
                arguments=args,
            )

            result = (validator or _validator).validate(tool_call, ctx)

            decision_label = result.decision.value.upper()
            _metrics.record_decision(
                decision=decision_label,
                tool_name=name,
                trigger_trust=result.trigger_trust.name,
                matched_patterns=list(result.matched_patterns),
                normalisation_flags=list(result.normalisation_flags),
            )
            if session_id:
                _anomaly.record(
                    session_id=session_id,
                    decision=decision_label,
                    trigger_trust=result.trigger_trust.name,
                    tool_name=name,
                )
            _decision_log.record(
                request_id=request_id,
                tool_name=name,
                decision=decision_label,
                reason=result.reason,
                trigger_source=result.trigger_source,
                trigger_trust=result.trigger_trust.name,
                matched_patterns=list(result.matched_patterns),
                normalisation_flags=list(result.normalisation_flags),
                data_classification=result.data_classification,
            )

            if result.blocked:
                blocked_count += 1
                blocked_explanations.append(
                    f"[SHIELDFLOW BLOCKED: {name}] {result.reason}"
                )
                _audit.log_blocked(
                    request_id=request_id,
                    tool_name=name,
                    reason=result.reason,
                    trigger_trust=result.trigger_trust.name,
                    trigger_source=result.trigger_source,
                    matched_patterns=list(result.matched_patterns),
                    normalisation_flags=list(result.normalisation_flags),
                    data_classification=result.data_classification,
                )
            elif result.needs_confirmation:
                allowed_calls.append(tc)
                _audit.log_confirmation_required(
                    request_id=request_id,
                    tool_name=name,
                    reason=result.reason,
                    trigger_trust=result.trigger_trust.name,
                    trigger_source=result.trigger_source,
                    data_classification=result.data_classification,
                )
            else:
                allowed_calls.append(tc)
                _audit.log_allowed(
                    request_id=request_id,
                    tool_name=name,
                    trigger_trust=result.trigger_trust.name,
                    trigger_source=result.trigger_source,
                    data_classification=result.data_classification,
                )

        allowed_count = len(allowed_calls)

        # Reconstruct the message with only allowed tool calls
        modified = dict(response_message)

        if allowed_calls:
            modified["tool_calls"] = allowed_calls
        else:
            modified.pop("tool_calls", None)

        if blocked_explanations:
            existing = modified.get("content") or ""
            block_text = "\n".join(blocked_explanations)
            modified["content"] = f"{existing}\n\n{block_text}".lstrip()

        return modified, blocked_count, allowed_count

    # ------------------------------------------------------------------ #
    # Helper: SSE stream reconstruction                                    #
    # ------------------------------------------------------------------ #

    async def _reconstruct_from_sse(
        stream_response: httpx.Response,
    ) -> dict[str, Any]:
        """Buffer an SSE stream and reconstruct a full chat-completion dict.

        Reads ``data: {JSON}`` lines from an httpx streaming response,
        accumulates ``delta`` fields per choice/tool-call index, and
        returns a single completion object in the same shape as a
        non-streaming ``POST /v1/chat/completions`` response.

        Args:
            stream_response: An open ``httpx.Response`` with
                ``stream=True`` that has not yet been read.

        Returns:
            Reconstructed ``dict`` with ``id``, ``model``, ``choices``
            (each with a full ``message``), etc.
        """
        completion: dict[str, Any] = {}
        # choice_index → entry dict (with private _tc_map)
        choices_acc: dict[int, dict[str, Any]] = {}

        async for raw_line in stream_response.aiter_lines():
            line = raw_line.strip()
            if not line.startswith("data:"):
                continue
            data = line[len("data:"):].strip()
            if data == "[DONE]":
                break
            try:
                chunk: dict[str, Any] = json.loads(data)
            except (json.JSONDecodeError, ValueError):
                continue

            # Capture stable top-level fields from the first chunk.
            for field in ("id", "object", "created", "model", "system_fingerprint"):
                if field in chunk and field not in completion:
                    completion[field] = chunk[field]

            for choice in chunk.get("choices", []):
                cidx: int = choice.get("index", 0)
                if cidx not in choices_acc:
                    choices_acc[cidx] = {
                        "index": cidx,
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [],
                        },
                        "finish_reason": None,
                        "_tc_map": {},  # tool_call_index → tc dict
                    }
                entry = choices_acc[cidx]

                if choice.get("finish_reason"):
                    entry["finish_reason"] = choice["finish_reason"]

                delta: dict[str, Any] = choice.get("delta", {})

                if "role" in delta:
                    entry["message"]["role"] = delta["role"]

                if delta.get("content"):
                    if entry["message"]["content"] is None:
                        entry["message"]["content"] = ""
                    entry["message"]["content"] += delta["content"]

                for tc_delta in delta.get("tool_calls", []):
                    tidx: int = tc_delta.get("index", 0)
                    tc_map: dict[int, dict[str, Any]] = entry["_tc_map"]
                    if tidx not in tc_map:
                        tc_map[tidx] = {
                            "id": "",
                            "type": "function",
                            "function": {"name": "", "arguments": ""},
                        }
                    tc = tc_map[tidx]
                    if tc_delta.get("id"):
                        tc["id"] = tc_delta["id"]
                    if tc_delta.get("type"):
                        tc["type"] = tc_delta["type"]
                    fn_delta = tc_delta.get("function", {})
                    if fn_delta.get("name"):
                        tc["function"]["name"] += fn_delta["name"]
                    if fn_delta.get("arguments"):
                        tc["function"]["arguments"] += fn_delta["arguments"]

        # Finalise: flatten tc_map → ordered list; clean up private key.
        for entry in choices_acc.values():
            tc_map = entry.pop("_tc_map")
            if tc_map:
                entry["message"]["tool_calls"] = [
                    tc_map[k] for k in sorted(tc_map)
                ]
            else:
                del entry["message"]["tool_calls"]
                if entry["message"]["content"] is None:
                    entry["message"]["content"] = ""

        completion.setdefault("object", "chat.completion")
        completion.setdefault("choices", [])
        completion["choices"] = [choices_acc[k] for k in sorted(choices_acc)]
        return completion

    # ------------------------------------------------------------------ #
    # Helper: SSE re-emission                                              #
    # ------------------------------------------------------------------ #

    def _make_sse_response(
        completion: dict[str, Any],
        extra_headers: dict[str, str],
    ) -> StreamingResponse:
        """Re-emit a (possibly modified) completion dict as an SSE stream.

        Produces the standard OpenAI SSE format: one ``data: {JSON}``
        line per delta event, terminated by ``data: [DONE]``.

        Args:
            completion: Full chat-completion dict (from
                :func:`_reconstruct_from_sse` or modified by validation).
            extra_headers: ShieldFlow response headers to include.

        Returns:
            A :class:`fastapi.responses.StreamingResponse` with
            ``Content-Type: text/event-stream``.
        """
        chunk_id: str = completion.get("id", f"chatcmpl-{uuid.uuid4().hex[:8]}")
        model: str = str(completion.get("model", "unknown"))
        created: int = int(completion.get("created", 0))
        choices: list[dict[str, Any]] = completion.get("choices", [])

        async def _generate() -> AsyncIterator[str]:
            for choice in choices:
                msg: dict[str, Any] = choice.get("message", {})
                cidx: int = choice.get("index", 0)
                finish: str = choice.get("finish_reason") or "stop"

                # Role + empty-content opener
                yield (
                    "data: "
                    + json.dumps({
                        "id": chunk_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": model,
                        "choices": [{
                            "index": cidx,
                            "delta": {
                                "role": msg.get("role", "assistant"),
                                "content": "",
                            },
                            "finish_reason": None,
                        }],
                    })
                    + "\n\n"
                )

                # Content delta (may be empty/None after blocks)
                content: str = msg.get("content") or ""
                if content:
                    yield (
                        "data: "
                        + json.dumps({
                            "id": chunk_id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model,
                            "choices": [{
                                "index": cidx,
                                "delta": {"content": content},
                                "finish_reason": None,
                            }],
                        })
                        + "\n\n"
                    )

                # Tool-call deltas
                for tidx, tc in enumerate(msg.get("tool_calls") or []):
                    # Header chunk: id + function name
                    yield (
                        "data: "
                        + json.dumps({
                            "id": chunk_id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model,
                            "choices": [{
                                "index": cidx,
                                "delta": {
                                    "tool_calls": [{
                                        "index": tidx,
                                        "id": tc.get("id", ""),
                                        "type": "function",
                                        "function": {
                                            "name": tc.get("function", {}).get("name", ""),
                                            "arguments": "",
                                        },
                                    }]
                                },
                                "finish_reason": None,
                            }],
                        })
                        + "\n\n"
                    )
                    # Arguments chunk
                    args: str = tc.get("function", {}).get("arguments", "")
                    if args:
                        yield (
                            "data: "
                            + json.dumps({
                                "id": chunk_id,
                                "object": "chat.completion.chunk",
                                "created": created,
                                "model": model,
                                "choices": [{
                                    "index": cidx,
                                    "delta": {
                                        "tool_calls": [{
                                            "index": tidx,
                                            "function": {"arguments": args},
                                        }]
                                    },
                                    "finish_reason": None,
                                }],
                            })
                            + "\n\n"
                        )

                # Finish-reason chunk
                yield (
                    "data: "
                    + json.dumps({
                        "id": chunk_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": model,
                        "choices": [{
                            "index": cidx,
                            "delta": {},
                            "finish_reason": finish,
                        }],
                    })
                    + "\n\n"
                )

            yield "data: [DONE]\n\n"

        return StreamingResponse(
            _generate(),
            media_type="text/event-stream",
            headers={
                **extra_headers,
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    # ------------------------------------------------------------------ #
    # Routes                                                               #
    # ------------------------------------------------------------------ #

    @app.post("/v1/chat/completions", response_model=None)
    async def chat_completions(request: Request) -> JSONResponse | StreamingResponse:
        """OpenAI-compatible chat completions endpoint.

        Authenticates the request, builds a trust-tagged context,
        forwards to the upstream provider, validates any tool_calls in
        the response, and returns the (possibly modified) completion
        with ShieldFlow headers.
        """
        rate_key = _authenticate(request)

        # Resolve per-tenant overrides (validator, rate limiter, user trust).
        t_validator, t_limiter, t_trust = _resolve_tenant(rate_key)

        request_id = str(uuid.uuid4())
        # Optional multi-turn session tracking.  Callers supply this header to
        # enable anomaly monitoring across multiple requests in the same session.
        session_id: str | None = request.headers.get("X-ShieldFlow-Session-ID") or None

        try:
            body: dict[str, Any] = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        messages: list[dict[str, Any]] = body.get("messages", [])
        model: str = body.get("model", "gpt-4")

        # Enforce request guardrails using tenant-specific rate limiter.
        _check_guardrails(request, messages, rate_key, limiter=t_limiter)

        # Build trust context using tenant-specific default user trust level.
        ctx = _build_context(messages, user_trust=t_trust)
        trust_summary = _trust_summary(ctx)
        min_trust_level = _min_trust(ctx)

        _metrics.record_request()
        _audit.log_request(
            request_id=request_id,
            model=model,
            message_count=len(messages),
            trust_summary=trust_summary,
        )

        # Detect streaming mode: buffer upstream SSE, validate, re-emit.
        is_streaming: bool = bool(body.get("stream"))

        # Forward to the upstream provider
        upstream_headers = {
            "Authorization": f"Bearer {config.upstream.api_key}",
            "Content-Type": "application/json",
        }
        upstream_url = f"{config.upstream.url}/v1/chat/completions"

        try:
            if is_streaming:
                # Streaming path: buffer entire SSE stream into a full
                # completion object so tool calls can be validated before
                # any content reaches the client.
                async with httpx.AsyncClient(
                    timeout=config.upstream.timeout
                ) as client:
                    async with client.stream(
                        "POST",
                        upstream_url,
                        json=body,
                        headers=upstream_headers,
                    ) as stream_resp:
                        if stream_resp.status_code != 200:
                            err_body = await stream_resp.aread()
                            try:
                                err_json = json.loads(err_body)
                            except (json.JSONDecodeError, ValueError):
                                err_json = {"error": err_body.decode(errors="replace")}
                            return JSONResponse(
                                content=err_json,
                                status_code=stream_resp.status_code,
                            )
                        response_data = await _reconstruct_from_sse(stream_resp)
            else:
                # Non-streaming path: single JSON response.
                async with httpx.AsyncClient(
                    timeout=config.upstream.timeout
                ) as client:
                    upstream_resp = await client.post(
                        upstream_url,
                        json=body,
                        headers=upstream_headers,
                    )

                if upstream_resp.status_code != 200:
                    return JSONResponse(
                        content=upstream_resp.json(),
                        status_code=upstream_resp.status_code,
                    )
                response_data = upstream_resp.json()

        except httpx.TimeoutException:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Upstream provider timed out",
            )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Upstream provider error: {exc}",
            )

        # Validate tool_calls in each choice (shared by both paths).
        total_blocked = 0
        total_allowed = 0

        resp_choices: list[dict[str, Any]] = response_data.get("choices", [])
        for i, choice in enumerate(resp_choices):
            msg = choice.get("message", {})
            if msg.get("tool_calls"):
                modified_msg, blocked, allowed = _validate_tool_calls(
                    msg, ctx, request_id,
                    session_id=session_id,
                    validator=t_validator,
                )
                response_data["choices"][i]["message"] = modified_msg
                total_blocked += blocked
                total_allowed += allowed

        _audit.log_response(
            request_id=request_id,
            blocked_count=total_blocked,
            allowed_count=total_allowed,
            model=response_data.get("model", model),
        )

        response_headers = {
            "X-ShieldFlow-Blocked": str(total_blocked),
            "X-ShieldFlow-Trust": min_trust_level.name,
            "X-ShieldFlow-Request-ID": request_id,
        }
        if is_streaming:
            # Signal to the client that the stream was buffered for
            # security validation before delivery.
            response_headers["X-ShieldFlow-Streamed"] = "buffered-validated"

        # Emit tenant label if configured for this token.
        if rate_key and rate_key in config.tenants:
            tenant_label = config.tenants[rate_key].label or rate_key[:8] + "..."
            response_headers["X-ShieldFlow-Tenant"] = tenant_label

        # Emit rate limit headers if rate limiting is enabled.
        if t_limiter.rpm > 0:
            rl_key = rate_key or (request.client.host if request.client else "unknown")
            response_headers["X-RateLimit-Remaining"] = str(t_limiter.remaining(rl_key))
            response_headers["X-RateLimit-Reset"] = str(t_limiter.reset_time(rl_key))

        # Emit session-level anomaly signals when session_id is present.
        if session_id:
            risk = _anomaly.risk_score(session_id)
            at_risk = _anomaly.is_anomalous(session_id)
            response_headers["X-ShieldFlow-Session-ID"] = session_id
            response_headers["X-ShieldFlow-Risk-Score"] = f"{risk:.4f}"
            if at_risk:
                response_headers["X-ShieldFlow-Session-At-Risk"] = "true"

        if is_streaming:
            return _make_sse_response(response_data, response_headers)
        return JSONResponse(content=response_data, headers=response_headers)

    @app.get("/health")
    async def health() -> dict[str, str]:
        """Liveness probe — returns 200 while the process is alive.

        Suitable for use as a Kubernetes ``livenessProbe`` or load-balancer
        health check.  Always returns HTTP 200 as long as the process is
        running; use ``/health/ready`` for readiness gating.
        """
        return {
            "status": "ok",
            "service": "shieldflow-proxy",
            "version": "0.2.0",
        }

    @app.get("/health/ready")
    async def health_ready(request: Request) -> JSONResponse:
        """Readiness probe — returns 200 when the proxy can serve traffic.

        Checks:
          * **upstream** — upstream URL and API key are configured.
          * **auth** — API-key list is consistent (open mode is valid).
          * **policy** — policy engine is loaded and operational.
          * **upstream_connectivity** — (optional) actual reachability check
            to the upstream URL. Pass ``?check_upstream=true`` to enable.

        Returns HTTP 200 with ``status: ready`` on success, or HTTP 503
        with ``status: not_ready`` and per-check detail on failure.
        Suitable for a Kubernetes ``readinessProbe``.
        """
        checks: dict[str, str] = {}
        failures: list[str] = []

        # 1. Upstream configuration
        if config.upstream.url:
            checks["upstream_url"] = "ok"
        else:
            checks["upstream_url"] = "missing"
            failures.append("upstream_url")

        if config.upstream.api_key:
            checks["upstream_key"] = "ok"
        else:
            checks["upstream_key"] = "missing"
            failures.append("upstream_key")

        # 2. Auth — open mode (no api_keys) is valid for dev
        checks["auth"] = "open_mode" if not config.api_keys else "ok"

        # 3. Policy engine — always loaded in create_app(); just confirm
        checks["policy"] = "ok"

        # 4. Optional upstream connectivity check
        check_upstream = request.query_params.get("check_upstream", "false").lower() == "true"
        if check_upstream and config.upstream.url and config.upstream.api_key:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    # Send a minimal request to check upstream is reachable
                    # Use models list endpoint as a lightweight probe
                    probe_url = f"{config.upstream.url}/v1/models"
                    resp = await client.get(
                        probe_url,
                        headers={"Authorization": f"Bearer {config.upstream.api_key}"},
                    )
                    if resp.status_code < 500:
                        checks["upstream_connectivity"] = "ok"
                    else:
                        checks["upstream_connectivity"] = f"error_{resp.status_code}"
                        failures.append("upstream_connectivity")
            except httpx.TimeoutException:
                checks["upstream_connectivity"] = "timeout"
                failures.append("upstream_connectivity")
            except httpx.RequestError as exc:
                checks["upstream_connectivity"] = f"error_{type(exc).__name__}"
                failures.append("upstream_connectivity")
        elif check_upstream:
            checks["upstream_connectivity"] = "skipped_missing_config"

        if failures:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "service": "shieldflow-proxy",
                    "checks": checks,
                    "failures": failures,
                },
            )

        return JSONResponse(
            status_code=200,
            content={
                "status": "ready",
                "service": "shieldflow-proxy",
                "checks": checks,
            },
        )

    @app.get("/health/detailed")
    async def health_detailed() -> dict[str, Any]:
        """Detailed status endpoint for observability and ops dashboards.

        Returns a rich JSON document covering:
          * **uptime** — seconds since the proxy started.
          * **config** — sanitised configuration summary (no secrets).
          * **metrics** — live counters from :class:`MetricsCollector`.
          * **anomaly** — session risk signals from :class:`AnomalyMonitor`.

        This endpoint is not recommended as a high-frequency health probe;
        use ``/health`` or ``/health/ready`` for that purpose.
        """
        uptime = time.monotonic() - _start_time
        metrics_snap = _metrics.snapshot()

        return {
            "status": "ok",
            "service": "shieldflow-proxy",
            "version": "0.2.0",
            "uptime_seconds": round(uptime, 2),
            "config": {
                "upstream_url": config.upstream.url,
                "upstream_timeout": config.upstream.timeout,
                "policy_path": config.policy_path,
                "audit_log_path": config.audit_log_path,
                "default_trust": config.default_trust.name,
                "api_keys_count": len(config.api_keys),
                "tenants_count": len(config.tenants),
                "rate_limit_rpm": config.rate_limit_rpm,
                "max_request_body_bytes": config.max_request_body_bytes,
                "max_messages_per_request": config.max_messages_per_request,
                "streaming_supported": True,
                "anomaly_detection": True,
            },
            "metrics": {
                "requests_total": metrics_snap.get("requests_total", 0),
                "decisions": metrics_snap.get("decisions", {}),
            },
            "anomaly": {
                "active_sessions": _anomaly.active_session_count(),
                "sessions_at_risk": _anomaly.sessions_at_risk(),
                "total_spikes": _anomaly.total_spikes(),
            },
        }

    # Register the security dashboard routes
    add_dashboard_routes(app, _decision_log)

    @app.get("/metrics")
    async def prometheus_metrics() -> PlainTextResponse:
        """Prometheus text exposition endpoint.

        Scrape this endpoint with Prometheus or any compatible collector.
        Content-Type: text/plain; version=0.0.4
        """
        combined = _metrics.prometheus_text() + _anomaly.prometheus_text()
        return PlainTextResponse(
            content=combined,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/metrics/json")
    async def metrics_json() -> JSONResponse:
        """JSON metrics snapshot for programmatic consumers.

        Returns aggregate counters, per-tool decision counts,
        top blocked patterns, and anomaly signals since proxy startup.
        """
        snapshot = _metrics.snapshot()
        snapshot["anomaly"] = {
            "active_sessions": _anomaly.active_session_count(),
            "total_spikes": _anomaly.total_spikes(),
            "sessions_at_risk": _anomaly.sessions_at_risk(),
        }
        return JSONResponse(snapshot, headers={"Cache-Control": "no-store"})

    return app


def run_server(
    config: ProxyConfig,
    host: str = "0.0.0.0",
    port: int = 8080,
    shutdown_timeout: float = 30.0,
) -> None:
    """Run the ShieldFlow proxy server with graceful shutdown handling.

    Args:
        config: Proxy configuration.
        host: Host to bind to.
        port: Port to listen on.
        shutdown_timeout: Seconds to wait for in-flight requests on shutdown.
    """
    import uvicorn
    from threading import Event

    global _shutdown_event, _shutdown_timeout
    _shutdown_timeout = shutdown_timeout

    # Create shutdown event
    shutdown_event = Event()
    _shutdown_event = shutdown_event

    # Register signal handlers
    signal.signal(signal.SIGTERM, _create_shutdown_handler())
    signal.signal(signal.SIGINT, _create_shutdown_handler())

    # Create the app
    app = create_app(config)

    # Add graceful shutdown endpoint and lifespan
    @app.on_event("shutdown")
    async def shutdown_event_handler():
        """Handle graceful shutdown."""
        shutdown_event.set()
        # Give time for in-flight requests to complete
        await asyncio.sleep(shutdown_timeout)
        # Flush audit logs
        if hasattr(app.state, "audit"):
            app.state.audit.close()
        print("✅ Graceful shutdown complete")

    print(f"🛡️ ShieldFlow proxy starting on {host}:{port}")
    print(f"   Upstream: {config.upstream.url}")
    print(f"   Timeout: {config.upstream.timeout}s")
    print("   Press Ctrl+C or send SIGTERM to stop gracefully")

    # Run server
    uvicorn.run(app, host=host, port=port, log_level="info")


# Need asyncio for shutdown handling
import asyncio
