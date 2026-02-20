# Metrics Reference

ShieldFlow exposes two metrics endpoints from the proxy process:

| Endpoint          | Format                    | Use                              |
|-------------------|---------------------------|----------------------------------|
| `GET /metrics`    | Prometheus text (v0.0.4)  | Prometheus / VictoriaMetrics scrape |
| `GET /metrics/json` | JSON snapshot           | Dashboards, alerting, debugging  |

## Available Metrics

### `shieldflow_requests_total`

Counter. Total proxy requests received since startup.

```promql
# Request rate per minute (5m window)
rate(shieldflow_requests_total[5m]) * 60
```

### `shieldflow_decisions_total`

Counter with labels: `decision`, `tool`, `trigger_trust`.

`decision` values: `BLOCK`, `ALLOW`, `CONFIRM`

```promql
# Block rate per minute
rate(shieldflow_decisions_total{decision="BLOCK"}[5m]) * 60

# Decision breakdown by type
sum by (decision) (shieldflow_decisions_total)

# Top blocked tools (last 24h)
topk(10, sum by (tool) (shieldflow_decisions_total{decision="BLOCK"}))

# Blocks from NONE-trust sources
sum(shieldflow_decisions_total{decision="BLOCK", trigger_trust="NONE"})
```

### `shieldflow_blocked_patterns_total`

Counter with label `pattern`. Incremented for each named injection pattern
that triggered a BLOCK decision.

Pattern names use the following prefixes:

- `pattern:<key>` — named regex in `NAMED_INJECTION_PATTERNS`
  (e.g. `pattern:ignore_previous_instructions`)
- `normalisation:<flag>` — sanitiser encoding detection
  (e.g. `normalisation:base64_injection`)

```promql
# Top 10 blocked patterns
topk(10, shieldflow_blocked_patterns_total)

# Encoding-based attacks only
shieldflow_blocked_patterns_total{pattern=~"normalisation:.*"}
```

### `shieldflow_normalisation_flags_total`

Counter with label `flag`. Raw sanitiser flags on BLOCK decisions.

Common values: `base64_injection`, `rot13_injection`, `homoglyphs`,
`compact_injection`, `hidden_html`, `invisible_unicode`.

```promql
# Encoding attack breakdown
sum by (flag) (shieldflow_normalisation_flags_total)
```

## Prometheus Setup

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: shieldflow
    static_configs:
      - targets: ["shieldflow-proxy:8080"]
    metrics_path: /metrics
    scrape_interval: 15s
```

## Grafana Setup

1. Add your Prometheus instance as a datasource in Grafana.
2. Import `docs/ops/grafana-dashboard.json` via
   **Dashboards → Import → Upload JSON**.
3. Select your Prometheus datasource and click **Import**.

The starter dashboard includes:

- **Total Requests** — stat panel
- **Block Rate** — time series (decisions/min)
- **Decision Mix** — block/allow/confirm breakdown
- **Top Blocked Patterns** — table of attack types
- **Trust Distribution** — decisions by trust level

## JSON Endpoint

`GET /metrics/json` returns:

```json
{
  "requests_total": 142,
  "decisions": {
    "block_total": 7,
    "allow_total": 130,
    "confirm_total": 5
  },
  "decisions_by_tool": {
    "exec": {"BLOCK": 3, "ALLOW": 0},
    "email.send": {"ALLOW": 45, "CONFIRM": 5},
    "file.read": {"ALLOW": 85, "BLOCK": 4}
  },
  "top_blocked_patterns": [
    ["pattern:ignore_previous_instructions", 4],
    ["normalisation:base64_injection", 2],
    ["pattern:authority_admin_please", 1]
  ],
  "top_normalisation_flags": [
    ["base64_injection", 2],
    ["homoglyphs", 1]
  ]
}
```
