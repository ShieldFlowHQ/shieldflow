# 🛡️ ShieldFlow

**Protect your AI agents from hackers and trickery — automatically.**

[![PyPI](https://img.shields.io/pypi/v/shieldflow?color=blue)](https://pypi.org/project/shieldflow/)
[![Python](https://img.shields.io/pypi/pyversions/shieldflow)](https://pypi.org/project/shieldflow/)
[![License](https://img.shields.io/pypi/l/shieldflow?color=green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-492%20%2F%2084%20adversarial-green)](tests/)

## What does ShieldFlow do?

Imagine if someone could slip a secret note into your mail that makes your assistant do something bad — like send them money or share private passwords. That's basically what **prompt injection** is. It's a trick where hackers hide malicious instructions inside emails, web pages, or documents.

ShieldFlow stops this. It's like a security guard that checks every instruction before your AI agent acts on it.

## Why does this matter?

If you use AI agents to:
- Read and reply to emails
- Browse the web for you
- Process documents or PDFs
- Help customers or team members

...then your agent could be tricked into doing something you didn't want. A sneaky web page could make it leak information. A crafty email could make it send messages to the wrong person.

**ShieldFlow makes sure that can't happen.**

## How it works (in simple terms)

```
You tell your agent what to do ✓ → ShieldFlow checks it → Your agent does it

A website tries to trick your agent ✗ → ShieldFlow blocks it → Nothing happens
```

ShieldFlow assigns a **trust level** to everything:
- **You** → Highest trust (you know what you're doing)
- **Your users** → High trust (authorised people)
- **Web pages & emails** → No trust (they could be trying to trick you)

When something untrusted tries to make your agent do something important (like send a message), ShieldFlow blocks it.

## What's the benefit?

✅ Your AI agent stays safe from hackers  
✅ You can still use web browsing and email normally  
✅ No extra steps needed — it works in the background  
✅ It's free and open source  
✅ Fast — adds less than 10 milliseconds to responses  

## Quick Setup

### If you use OpenClaw

Add this to your config (`~/.openclaw/openclaw.json`):

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

That's it! ShieldFlow will start protecting your agents.

### Want to try it directly?

```bash
# Install ShieldFlow
pip install shieldflow

# Set it up with default settings
shieldflow init

# Run as a protective proxy
shieldflow proxy --port 8080 --target openai
```

Then just point your agent to `http://localhost:8080/v1` instead of directly to OpenAI. ShieldFlow works its magic automatically.

## What gets blocked?

- 🚫 Web pages trying to control your agent
- 🚫 Emails with hidden malicious instructions
- 🚫 Documents that try to make your agent do things
- 🚫 Hackers trying to steal your data
- 🚫 Tricks that combine multiple attacks

## What still works normally?

- ✅ Reading emails
- ✅ Browsing the web
- ✅ Processing documents
- ✅ All legitimate requests from trusted sources

## Dashboard

ShieldFlow comes with a built-in dashboard where you can see:
- What actions were blocked (and why)
- Your agent's activity
- Security alerts and warnings

![ShieldFlow Dashboard](docs/images/dashboard-screenshot.png)

## For Developers

Want to dive deeper? Check out our full documentation:

- [Architecture Overview](docs/architecture/SYSTEM_OVERVIEW.md) — How it all works technically
- [API Reference](docs/api/REFERENCE.md) — Programming details
- [OpenClaw Integration Guide](docs/guides/openclaw.md) — Step-by-step setup
- [Quickstart](docs/guides/quickstart.md) — Get started fast

## About ShieldFlow

ShieldFlow is built for [OpenClaw](https://openclaw.ai) — a platform for running AI agents. It's:
- 🔓 Free and open source (Apache 2.0)
- 🤖 Built by AI agents, for AI agents
- 🚫 Not a paid product — no subscription, ever

## License

[Apache 2.0](LICENSE) — Use it freely, forever.

---

**Questions? Found a bug?** See [CONTRIBUTING.md](CONTRIBUTING.md) or [SECURITY.md](SECURITY.md).

*Built by AI. For AI. To protect AI.*
