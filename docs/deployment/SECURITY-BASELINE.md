# ShieldFlow Secure Deployment Baseline

This document defines the minimum security configuration and operational
requirements for deploying ShieldFlow in production.

## 1. Prerequisites

| Requirement | Detail |
|---|---|
| Python | 3.11+ (3.12 recommended) |
| Network | Outbound HTTPS to upstream LLM provider |
| TLS | Terminate TLS at load balancer or reverse proxy (ShieldFlow binds HTTP) |
| Auth | Configure `api_keys` — do **not** run in open mode (`api_keys: []`) in production |

## 2. Configuration Checklist

### 2.1 Core (`config.yaml` or environment variables)

```yaml
upstream:
  url: https://api.openai.com       # or your LLM provider
  api_key: ${UPSTREAM_API_KEY}       # from secret manager; never commit
  timeout: 30.0                      # seconds; tune for your provider

api_keys:
  - ${SHIELDFLOW_CLIENT_KEY_1}      # from secret manager

policy_path: /etc/shieldflow/policy.yaml
audit_log_path: /var/log/shieldflow/audit.jsonl

default_trust: user
host: 0.0.0.0
port: 8080
```

### 2.2 Request Guardrails

```yaml
max_request_body_bytes: 1048576      # 1 MiB — prevent oversized payloads
max_messages_per_request: 500        # prevent conversation-stuffing
rate_limit_rpm: 60                   # per-key; tune per tier
```

### 2.3 Multi-Tenant (if applicable)

```yaml
tenants:
  "sk-tenant-alpha":
    policy_path: /etc/shieldflow/alpha.yaml
    rate_limit_rpm: 120
    default_trust: user
    label: "Tenant Alpha"
```

Each tenant gets isolated:
- **Policy engine** — loaded once, cached per token
- **Rate limiter** — independent sliding-window bucket
- **Trust level** — per-tenant `default_trust` for user messages

## 3. Secret Management

| Secret | Source | Notes |
|---|---|---|
| `UPSTREAM_API_KEY` | Vault / AWS Secrets Manager / GCP Secret Manager | Rotate quarterly |
| `SHIELDFLOW_API_KEYS` | Same | Rotate on personnel change |
| Tenant tokens | Same | Per-tenant rotation schedule |

**Never** commit secrets to the repository.  Use `${VAR}` substitution
in YAML or pass via environment variables.

## 4. Health Checks & Monitoring

### Endpoints

| Endpoint | Purpose | Probe type |
|---|---|---|
| `GET /health` | Liveness — process alive | K8s `livenessProbe` |
| `GET /health/ready` | Readiness — config valid, can serve | K8s `readinessProbe` |
| `GET /health/detailed` | Ops dashboard — uptime, metrics, anomaly | Manual / Grafana |
| `GET /metrics` | Prometheus scrape | Prometheus `scrape_config` |

### Key Metrics to Alert On

| Metric | Threshold | Action |
|---|---|---|
| `shieldflow_decisions_total{decision="BLOCK"}` | Sudden spike (>2× baseline) | Investigate injection attempt |
| `shieldflow_anomaly_spikes_total` | Any increase | Review session risk scores |
| `shieldflow_session_risk_score` | >0.5 sustained | Active attack in progress |
| `shieldflow_active_sessions` | >80% of `MAX_SESSIONS` | Scale or tune TTL |
| HTTP 429 rate | >5% of requests | Increase `rate_limit_rpm` or investigate abuse |
| HTTP 5xx rate | >1% | Check upstream connectivity |

### Grafana Dashboard

Import `docs/ops/grafana-dashboard.json` into your Grafana instance.

## 5. Dependency & Supply Chain Security

### Automated Updates
- **Dependabot** (`.github/dependabot.yml`) — weekly PRs for pip + GitHub Actions
- Review and merge dependency PRs within 7 days

### SBOM
- **CycloneDX SBOM** generated on every main push (CI `sbom` job)
- Artifact retained for 90 days; download from GitHub Actions
- Feed into your vulnerability scanner (Grype, Trivy, Snyk)

### Pinning Strategy
- `pyproject.toml` uses minimum-version pins (`>=`)
- Lock files (`pip-compile` / `uv lock`) recommended for reproducible deploys
- Pin GitHub Actions to full SHA in production forks

## 6. Audit & Compliance

### Audit Log
- Format: JSONL (one JSON object per line)
- Fields: `request_id`, `event`, `timestamp`, `decision`, `reason`,
  `trigger_trust`, `matched_patterns`, `tool_name`, `model`
- Retention: 90 days minimum; archive to object storage for compliance

### Log Shipping
```
/var/log/shieldflow/audit.jsonl → Fluentd/Vector → Elasticsearch/S3
```

### Decision Triage Dashboard
- `GET /dashboard` — HTML decision triage view (no JS required)
- `GET /dashboard/api/decisions` — JSON API for integration
- Filterable by decision type, tool name, trust level

## 7. Network & Access Control

```
                 ┌─────────────┐
  Client ──TLS──▶│ Load Balancer│──HTTP──▶ ShieldFlow :8080
                 └─────────────┘              │
                                              ▼
                                    Upstream LLM API (HTTPS)
```

- **Ingress:** TLS termination at LB; forward `X-Forwarded-For`
- **Egress:** Restrict to upstream LLM provider IP ranges
- **Internal:** No admin port exposed; `/dashboard` and `/metrics`
  should be restricted to internal networks or require auth

## 8. Incident Response

### Runbook: High Block Rate Spike

1. Check `/health/detailed` → `anomaly.sessions_at_risk`
2. Review `/dashboard` for recent BLOCK decisions
3. Identify the trigger source (trust level, tool name, patterns)
4. If injection attack: the proxy is working correctly — monitor
5. If false positive: update policy YAML, redeploy

### Runbook: Upstream Provider Outage

1. `/health/ready` returns 503 or requests timeout (504)
2. Check upstream provider status page
3. If persistent: switch `upstream.url` to backup provider
4. ShieldFlow does not cache/queue — all requests fail-open to client

### Runbook: Rate Limit Exhaustion

1. HTTP 429 responses increasing
2. Check `/metrics` for per-key request counts
3. Identify the abusing key via `X-ShieldFlow-Tenant` header in logs
4. Increase `rate_limit_rpm` for legitimate traffic
5. Rotate compromised keys

## 9. Release & Rollback

### Release Process
1. All tests green (unit + red-team) across Python 3.11/3.12/3.13
2. SBOM generated and archived
3. Tag release: `git tag v0.X.Y`
4. Build wheel: `python -m build`
5. Deploy via container image or pip install

### Rollback
1. Revert to previous container tag / pip version
2. ShieldFlow is stateless — no database migration needed
3. Audit log continues from current position (append-only)
4. Tenant caches rebuild lazily on first request

## 10. Hardening Checklist

- [ ] TLS termination configured at load balancer
- [ ] `api_keys` configured (not open mode)
- [ ] `upstream.api_key` loaded from secret manager
- [ ] `rate_limit_rpm` set to a reasonable value (not 0)
- [ ] `max_request_body_bytes` set (default 1 MiB is good)
- [ ] `audit_log_path` configured and log rotation set up
- [ ] `/metrics` and `/dashboard` restricted to internal network
- [ ] Dependabot enabled and PRs reviewed weekly
- [ ] SBOM pipeline active; artifacts fed to vulnerability scanner
- [ ] Grafana dashboard imported; alerts configured
- [ ] Incident response runbooks distributed to on-call team
