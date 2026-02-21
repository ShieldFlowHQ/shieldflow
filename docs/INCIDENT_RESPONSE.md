# Security Incident Response Runbook

## Emergency Contacts
- Security Team: security@shieldflow.example
- On-call: oncall@shieldflow.example

## Incident Types

### 1. Suspicious Activity Detected
**Symptoms**: Unusual number of blocked requests, anomalous session behavior

**Response**:
1. Check dashboard for blocked requests: `/dashboard`
2. Review audit logs: `tail -f /var/log/shieldflow/audit.jsonl`
3. Check anomaly metrics: `/metrics/json`
4. If targeted attack: block source IP at firewall level

### 2. Data Exfiltration Attempt
**Symptoms**: DLP classifier triggered, sensitive data in outbound messages

**Response**:
1. Identify the request: check logs for DLP_BLOCK events
2. Identify the source user/token
3. Quarantine if needed: revoke API key
4. Review what data was exfiltrated
5. Report to compliance team

### 3. Service Outage
**Symptoms**: Proxy not responding, health check fails

**Response**:
1. Check if proxy is running: `curl http://localhost:8080/health`
2. Check logs for errors
3. Restart if needed: `pkill -HUP shieldflow` (graceful) or `systemctl restart shieldflow`
4. Contact on-call if not recovered in 15 minutes

### 4. Configuration Error
**Symptoms**: All requests blocked, or all requests allowed

**Response**:
1. Check current policy: `shieldflow validate config.yaml`
2. Review recent config changes in git
3. Roll back if needed
4. Test with: `shieldflow proxy --config /tmp/test.yaml`

## Recovery
After incident:
1. Document timeline
2. Update runbook if gaps found
3. Schedule post-mortem within 48 hours
