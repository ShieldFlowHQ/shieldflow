# 🛡️ ShieldFlow

**The easy way to keep your AI agents safe from hackers.**

[![PyPI](https://img.shields.io/pypi/v/shieldflow?color=blue)](https://pypi.org/project/shieldflow/)
[![Python](https://img.shields.io/pypi/pyversions/shieldflow)](https://pypi.org/project/shieldflow/)
[![License](https://img.shields.io/pypi/l/shieldflow?color=green)](LICENSE)

---

## ⚡ One-Line Summary

ShieldFlow is a **security guard** that sits between your AI agent and the outside world — checking every request to stop hackers from tricking your agent into doing something bad.

---

## 🤔 Why Does This Matter?

If you use AI agents to do helpful things like:
- Read and reply to emails
- Browse the web
- Process documents or PDFs
- Help customers or teammates

...hackers could try to trick your agent into:
- Leaking private information 💸
- Sending messages to the wrong person 📧
- Buying something fraudulent 🛒
- Giving away passwords 🔐

**ShieldFlow stops that from happening.**

---

## 📦 Install (One Command)

```bash
pip install shieldflow
```

That's it! You're ready to go.

---

## 🚀 How to Use It

### Option 1: Use with OpenClaw (Easiest)

If you use [OpenClaw](https://openclaw.ai), just add this to your config:

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

Done! Your agents are now protected.

### Option 2: Run as a Proxy

Want to protect any AI agent? Run ShieldFlow as a protective barrier:

```bash
# Start ShieldFlow
shieldflow proxy --port 8080 --target openai
```

Then point your agent to `http://localhost:8080/v1` instead of OpenAI directly.

That's it! ShieldFlow now checks every request before it reaches your agent.

---

## 🔍 How Does It Work?

```
Your request → ShieldFlow checks it → Agent gets safe request ✓

Hacker trick → ShieldFlow blocks it ✗
```

ShieldFlow gives every source a **trust score**:

| Source | Trust Level |
|--------|-------------|
| You | Full trust |
| Your team | High trust |
| Websites & emails | No trust |

When something untrusted (like a website) tries to make your agent do something important (like send an email), ShieldFlow says "nope" and blocks it.

---

## ✨ What ShieldFlow Blocks

- ❌ Web pages that try to control your agent
- ❌ Emails with hidden sneaky instructions  
- ❌ Documents that try to make your agent do things
- ❌ Hackers trying to steal your data

## ✨ What Still Works Normally

- ✅ Reading emails
- ✅ Browsing the web
- ✅ Processing documents
- ✅ Requests from you and your team

---

## 🎯 What's the Upside?

- 🔒 Your AI agent can't be tricked by hackers
- 🌐 You can still browse the web and read emails normally
- ⚡ It's fast — adds less than 10ms to responses
- 🎉 Free and open source — no payments, ever
- 🛠️ Works quietly in the background

---

## 📚 Want to Learn More?

- [Quickstart Guide](docs/guides/quickstart.md) — Get up and running fast
- [Architecture Overview](docs/architecture/SYSTEM_OVERVIEW.md) — How it works technically
- [OpenClaw Integration](docs/guides/openclaw.md) — Step-by-step setup

---

## 📝 About ShieldFlow

ShieldFlow was built for [OpenClaw](https://openclaw.ai) — a platform for running AI agents.

- 🔓 Free and open source (Apache 2.0 license)
- 🤖 Built by AI, for AI
- 🚫 No subscriptions, ever

---

## 📜 License

[Apache 2.0](LICENSE) — Use it freely, forever.

---

*Built by AI. For AI. To protect AI.*
