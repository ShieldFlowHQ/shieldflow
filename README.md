# 🛡️ ShieldFlow

**The easy way to keep your AI agents safe from hackers.**

[![PyPI](https://img.shields.io/pypi/v/shieldflow?color=blue)](https://pypi.org/project/shieldflow/)
[![Python](https://img.shields.io/pypi/pyversions/shieldflow)](https://pypi.org/project/shieldflow/)
[![License](https://img.shields.io/pypi/l/shieldflow?color=green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-492%20%2F%2084%20adversarial-green)](tests/)

---

## 👋 What is this?

Think of ShieldFlow as a **security guard** for your AI agents.

Just like a guard checks who comes into a building, ShieldFlow checks every instruction before your AI agent acts on it. It stops sneaky tricks from working — so your agent stays safe.

## 🤔 Why should I care?

If you use AI agents to do helpful things like:
- Read and reply to emails
- Browse the web
- Process documents or PDFs
- Help customers or teammates

...then hackers could potentially trick your agent into doing something bad. Like leaking private information or sending messages to the wrong person.

**ShieldFlow stops that from happening.** It's like having a watchful friend looking over your agent's shoulder — but automatically.

## 🔍 How does it work?

Here's the simple version:

```
You ask your agent to do something → ShieldFlow checks it → Agent does it ✓

A tricky website tries to trick your agent → ShieldFlow blocks it ✗
```

ShieldFlow gives everything a **trust score**:
- **You** → Full trust (you know what you're doing)
- **Your team** → High trust (authorized people)
- **Websites & emails** → No trust (they might be trying to trick you)

When something untrusted tries to make your agent do something important (like send an email), ShieldFlow says "nope" and blocks it.

## ✨ What's the upside?

- 🔒 Your AI agent can't be tricked by hackers
- 🌐 You can still browse the web and read emails normally
- ⚡ It's fast — adds less than 10 milliseconds to responses
- 🎉 It's free and open source — no payments, ever
- 🛠️ Works quietly in the background

## 🚀 Get Started (Super Quick)

### Option 1: If you use OpenClaw

Just add this to your config (`~/.openclaw/openclaw.json`):

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

Done! ShieldFlow is now protecting your agents.

### Option 2: Try it directly

```bash
# Install ShieldFlow
pip install shieldflow

# Set it up
shieldflow init

# Run it as a protective barrier
shieldflow proxy --port 8080 --target openai
```

Then point your agent to `http://localhost:8080/v1` instead of OpenAI directly. That's it!

## 🚫 What gets blocked?

- Web pages that try to control your agent
- Emails with hidden sneaky instructions
- Documents that try to make your agent do things
- Hackers trying to steal your data

## ✅ What still works normally?

- Reading emails ✅
- Browsing the web ✅
- Processing documents ✅
- Requests from you and your team ✅

## 📊 Want to see what's happening?

ShieldFlow has a dashboard where you can see:
- What was blocked (and why)
- Your agent's activity
- Any security alerts

![ShieldFlow Dashboard](docs/images/dashboard-screenshot.png)

## 👨‍💻 For Developers

Want to dig deeper? Here's where to go:

- [Quickstart Guide](docs/guides/quickstart.md) — Get up and running fast
- [Architecture Overview](docs/architecture/SYSTEM_OVERVIEW.md) — How it works technically
- [OpenClaw Integration](docs/guides/openclaw.md) — Step-by-step setup
- [API Reference](docs/api/REFERENCE.md) — Programming details

## 📝 About ShieldFlow

ShieldFlow was built for [OpenClaw](https://openclaw.ai) — a platform for running AI agents.

- 🔓 Free and open source (Apache 2.0 license)
- 🤖 Built by AI, for AI
- 🚫 No subscriptions, ever

## 📜 License

[Apache 2.0](LICENSE) — Use it freely, forever.

---

**Something broken?** Check out [CONTRIBUTING.md](CONTRIBUTING.md) or [SECURITY.md](SECURITY.md).

*Built by AI. For AI. To protect AI.*
