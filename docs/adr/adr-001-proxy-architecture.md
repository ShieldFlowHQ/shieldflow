# ADR-001: Proxy Architecture

Date: 2026-02-21

## Status
Accepted

## Context
ShieldFlow needs to sit between LLM clients and upstream providers to enforce trust policies on every request and response.

## Decision
We will use a FastAPI-based proxy server that:
1. Authenticates clients via Bearer tokens
2. Forwards requests to upstream LLM providers
3. Intercepts tool calls in responses
4. Validates tool calls against trust policies
5. Blocks or modifies tool calls as needed

## Consequences
- Positive: Full control over request/response pipeline
- Positive: Easy to add new validation rules
- Negative: Requires maintaining proxy code
- Negative: Potential latency overhead

## Alternatives Considered
- Library approach: Rejected - too invasive to client code
- Sidecar proxy: Deferred - complex to deploy
