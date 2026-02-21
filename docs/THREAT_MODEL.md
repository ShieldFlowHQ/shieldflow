# Threat Model

This document outlines the security threats ShieldFlow is designed to mitigate and the threats it does not protect against.

## Threats Mitigated

### Prompt Injection
ShieldFlow validates all tool calls against trust policies to prevent malicious instructions from triggering dangerous actions.

### Data Exfiltration
DLP classification blocks sensitive data (API keys, passwords, SSNs) from being sent to external destinations.

### Trust Escalation
The trust model ensures untrusted sources cannot perform privileged actions.

### Rate Limiting
Built-in rate limiting prevents abuse and DoS.

## Threats Not Mitigated

### Upstream Provider Compromise
If the upstream LLM provider is compromised, ShieldFlow cannot help.

### Client-Side Attacks
ShieldFlow runs server-side and cannot protect against compromised clients.

### Insider Threats
Trusted users with malicious intent may still be able to exfiltrate data.

### TLS/Encryption
ShieldFlow does not provide encryption - it should be deployed behind a reverse proxy with TLS.
