# ShieldFlow Roadmap

This roadmap translates the current status in `README.md`, `CHANGELOG.md`, and `docs/architecture/THREAT_MODEL.md` into execution phases.

---

## Phase A — Hardening ✅ COMPLETE

Objective: eliminate known active bypass classes and raise confidence to enforcement-by-default.

1. ✅ Build a normalization pipeline in `ActionValidator` (base64 decode, HTML entity decode, Unicode NFKC + homoglyph mapping, ROT13 detection pass).
2. ✅ Expand injection detection beyond static patterns (authority/social-engineering phrasing coverage + robust action linkage).
3. ✅ Fix email extraction and overlap edge cases (trailing punctuation and normalization-safe comparisons).
4. ✅ Scan AGENT-trust content for injection patterns (separate "scannable" from "allowed trust").
5. ✅ Convert current red-team xfails tied to active bypasses into passing tests and gate release on zero known bypass regressions.

Exit criteria — **all met:**
- ✅ All 84 red-team bypass tests pass.
- ✅ Hardening paths covered by deterministic unit + red-team tests.
- ⏳ `v0.2.0` tag pending (all code ready).

## Phase B — Observability & Dashboard ✅ COMPLETE

Objective: make security decisions auditable and operationally useful.

1. ✅ Extend audit schema with attribution fields (trigger block, trust chain, normalization hits, classifier outcomes).
2. ✅ Add metrics emission for allow/block/confirm decisions and top blocked patterns.
3. ✅ Build a minimal dashboard view (recent decisions, blocked actions, confirmation queue, trend panels).
4. ✅ Implement session-level anomaly signals (multi-turn risk spikes after untrusted ingestion).

Exit criteria — **all met:**
- ✅ Operators can answer "why was this blocked/allowed?" from UI + logs.
- ✅ Baseline dashboards and alerts deployable in proxy mode.
- ✅ Prometheus metrics: `shieldflow_decisions_total`, `shieldflow_session_risk_score`, `shieldflow_anomaly_spikes_total`.
- ✅ Frontend dashboard demo with decision triage UI.

## Phase C — Hosted Cloud Readiness ✅ COMPLETE

Objective: prepare ShieldFlow for managed multi-tenant operation.

1. ✅ Add streaming support and request limits in proxy (rate/size/time controls).
2. ✅ Introduce tenant-aware policy management and key rotation workflows.
3. ✅ Formalize MCP trust policy and server verification model.
4. ✅ Define secure deployment baseline (SBOM, dependency policy, release signing, rollback runbooks).
5. ✅ Add production SLOs, health checks, and incident response playbooks.

Exit criteria — **all met:**
- ✅ Hosted architecture reviewed for security + reliability.
- ✅ Multi-tenant controls and operations docs are release-ready.
- ✅ SSE streaming with buffer-validate-re-emit security model.
- ✅ MCP trust policy formalized with per-server policies.
- ✅ Dependabot + SBOM CI pipeline active.

---

## Phase D — Production Hardening & v0.2.0 Release

Objective: harden remaining gaps, tag the milestone release, and prepare for community adoption.

### D.1 — Test coverage hardening
1. Cover `session.py` (55% → 90%+): session lifecycle, expiry, anomaly integration.
2. Cover `context.py` `to_messages()` serialization path (74% → 90%+).
3. Cover `cli.py` entry points with integration tests.
4. Add property-based / fuzz tests for the sanitiser pipeline.

### D.2 — v0.2.0 release
1. Update `CHANGELOG.md` with all Phase A–C work.
2. Bump version in `pyproject.toml` and `__init__.py`.
3. Tag `v0.2.0` on main.
4. Build and publish wheel to PyPI (or GitHub Releases).

### D.3 — Community readiness (Issue #11)
1. Write `CONTRIBUTING.md` guide with development setup, test commands, PR process.
2. Add issue templates for bug reports, feature requests, and security vulnerabilities.
3. Add `SECURITY.md` with responsible disclosure policy.
4. First call for contributors.

### D.4 — Advanced security features
1. Semantic DLP: content classification beyond pattern matching.
2. Adaptive policy: auto-escalate confirmation requirements based on anomaly signals.
3. MCP manifest verification: cryptographic server identity pinning.
4. Real-time streaming validation (validate tool calls as they arrive, not buffered).

Exit criteria:
- v0.2.0 published with full changelog.
- Test coverage ≥ 95% on security-critical modules.
- Community contribution path documented and first external PR merged.
