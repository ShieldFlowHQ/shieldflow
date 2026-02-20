# 🛡️ ShieldFlow

**The easy way to keep your AI agents safe from hackers.**

[![PyPI](https://img.shields.io/pypi/v/shieldflow?color=blue)](https://pypi.org/project/shieldflow/)
[![Python](https://img.shields.io/pypi/pyversions/shieldflow)](https://pypi.org/project/shieldflow/)
[![License](https://img.shields.io/pypi/l/shieldflow?color=green)](LICENSE)

---

## 🤔 What is this?

Imagine your AI assistant is like a helpful intern. Now imagine a trickster slips a fake note into your inbox that makes the intern do something bad — like transfer money or share secrets.

That's called **prompt injection**. It's a real problem.

**ShieldFlow stops this from happening.** Think of it as a security guard that checks everything before your AI agent acts on it.

---

## 👀 See it in action

```
Good request (from you)      → ✅ ShieldFlow says "OK" → Your agent does it
Tricky request (from a website) → ❌ ShieldFlow says "Nope" → Blocked!
```

---

## ✨ What ShieldFlow does

| Shields you from | But still lets you |
|------------------|-------------------|
| 🦹 Hackers trying to trick your agent | 📧 Read emails normally |
| 😈 Sneaky websites with hidden commands | 🌐 Browse the web |
| 📄 Dangerous documents | 📑 Process documents |
| 🎭 Fake instructions hiding in plain sight | ✅ Use all your AI tools |

---

## 🚀 Get started in 30 seconds

### Option 1: If you use OpenClaw (easiest!)

Just add this to your settings:

```json
{
  "security": {
    "shieldflow": {
      "enabled": true
    }
  }
}
```

Done! You're protected. 🎉

### Option 2: Try it yourself

```bash
pip install shieldflow
shieldflow init
shieldflow proxy --port 8080
```

Then use `http://localhost:8080` instead of your normal AI endpoint. That's it!

---

## 🤔 Why should you care?

If you use AI agents to:
- Read your emails
- Search the web
- Handle documents
- Talk to customers

...then a sneaky website or email could make your agent do something you didn't ask for. **ShieldFlow prevents that.**

---

## 💡 What makes ShieldFlow special?

- 🔒 **Blocks the tricks** — hackers can't fool your AI
- ⚡ **Super fast** — you won't even notice it's there
- 💜 **Free forever** — no paid plans, no subscriptions
- 🔓 **Open source** — anyone can check the code
- 🤖 **Built by AI, for AI**

---

## 📸 What does it look like?

ShieldFlow has a simple dashboard where you can see:

- What was blocked (and why)
- Your agent's activity
- Any security warnings

![ShieldFlow Dashboard](docs/images/dashboard-screenshot.png)

---

## 🆘 Need help?

- 📖 [Full Documentation](docs/guides/quickstart.md) — Step-by-step guides
- 🐛 [Report a Bug](CONTRIBUTING.md) — Help us improve
- 💬 [Ask a Question](SECURITY.md) — We're here to help

---

## 📜 The boring stuff

- **License:** [Apache 2.0](LICENSE) — Use it however you want
- **Built for:** [OpenClaw](https://openclaw.ai)
- **Cost:** Free. Always.

---

*Made by AI. For AI. To protect AI.* 🤖🛡️
