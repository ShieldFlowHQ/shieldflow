# Security Policy

## Reporting a Vulnerability

ShieldFlow is a security product. We take vulnerabilities seriously.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report them via:
- Email: security@shieldflow.dev (placeholder — update when domain is live)
- Or open a private security advisory on GitHub

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### What to Expect

- Acknowledgement within 48 hours
- Assessment and timeline within 1 week
- Credit in the security advisory (unless you prefer anonymity)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | ✅ (current development) |

## Security Design Principles

ShieldFlow follows these security principles:

1. **Fail secure**: When in doubt, block. Unknown actions default to OWNER-only.
2. **Defence in depth**: Multiple independent layers — signing, policy, sanitisation, DLP.
3. **Least privilege**: Actions require the minimum trust level necessary.
4. **No trust escalation**: Trust assigned at ingestion is final.
5. **Constant-time comparison**: HMAC verification uses constant-time comparison to prevent timing attacks.
6. **Ephemeral keys**: Session signing keys are generated per-session and never persisted.

## Known Limitations

See the [Trust Model documentation](docs/architecture/TRUST_MODEL.md#limitations) for known limitations of the current approach.
