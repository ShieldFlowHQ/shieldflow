# Auto-Detect Upstream LLM from OpenClaw

## Research Finding: ✅ FEASIBLE

OpenClaw stores LLM configuration in `~/.openclaw/openclaw.json`:

```json
{
  "auth": {
    "profiles": {
      "anthropic:default": {
        "provider": "anthropic",
        "mode": "token"
      },
      "minimax:default": {
        "provider": "minimax", 
        "mode": "api_key"
      }
    }
  }
}
```

## How It Would Work

1. ShieldFlow reads OpenClaw config at startup
2. Extracts the default auth profile (e.g., `anthropic:default`)
3. Uses that provider's credentials automatically
4. No duplicate API key configuration needed

## Benefits
- Zero-config integration with OpenClaw
- Automatically uses whatever LLM OpenClaw is configured for
- No user setup beyond "enable ShieldFlow"

## Implementation
- Add `openclaw_auto_detect: true` option in ShieldFlow config
- Read from `~/.openclaw/openclaw.json` on startup
- Fall back to explicit config if auto-detect disabled
