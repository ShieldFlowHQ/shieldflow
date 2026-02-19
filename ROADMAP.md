# ShieldFlow Roadmap (Next Phase)

This roadmap translates the current status in `README.md`, `CHANGELOG.md`, and `docs/architecture/THREAT_MODEL.md` into execution phases.

## Phase A — Hardening (close remaining xfails)

Objective: eliminate known active bypass classes and raise confidence to enforcement-by-default.

1. Build a normalization pipeline in `ActionValidator` (base64 decode, HTML entity decode, Unicode NFKC + homoglyph mapping, ROT13 detection pass).
2. Expand injection detection beyond static patterns (authority/social-engineering phrasing coverage + robust action linkage).
3. Fix email extraction and overlap edge cases (trailing punctuation and normalization-safe comparisons).
4. Scan AGENT-trust content for injection patterns (separate "scannable" from "allowed trust").
5. Convert current red-team xfails tied to active bypasses into passing tests and gate release on zero known bypass regressions.

Exit criteria:
- All currently active bypass tests pass.
- New hardening paths are covered by deterministic unit + red-team tests.
- `v0.2.0` tagged as hardening release candidate.

## Phase B — Observability & Dashboard

Objective: make security decisions auditable and operationally useful.

1. Extend audit schema with attribution fields (trigger block, trust chain, normalization hits, classifier outcomes).
2. Add metrics emission for allow/block/confirm decisions and top blocked patterns.
3. Build a minimal dashboard view (recent decisions, blocked actions, confirmation queue, trend panels).
4. Implement session-level anomaly signals (multi-turn risk spikes after untrusted ingestion).

Exit criteria:
- Operators can answer "why was this blocked/allowed?" from UI + logs.
- Baseline dashboards and alerts are deployable in proxy mode.

## Phase C — Hosted Cloud Readiness

Objective: prepare ShieldFlow for managed multi-tenant operation.

1. Add streaming support and request limits in proxy (rate/size/time controls).
2. Introduce tenant-aware policy management and key rotation workflows.
3. Formalize MCP trust policy and server verification model.
4. Define secure deployment baseline (SBOM, dependency policy, release signing, rollback runbooks).
5. Add production SLOs, health checks, and incident response playbooks.

Exit criteria:
- Hosted architecture reviewed for security + reliability.
- Multi-tenant controls and operations docs are release-ready.
