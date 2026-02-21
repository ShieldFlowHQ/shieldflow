#!/usr/bin/env python3
"""Multi-tenant ShieldFlow demo script.

This script demonstrates making requests to ShieldFlow with different
tenant tokens, each receiving different policy enforcement.

Usage:
    export OPENAI_API_KEY="your-key"
    python multi_tenant_demo.py

Requirements:
    - ShieldFlow proxy running: shieldflow proxy --config multi_tenant.yaml
    - OpenAI API key set
"""

import os
import httpx

# ShieldFlow proxy URL
PROXY_URL = os.environ.get("SHIELDFLOW_URL", "http://localhost:8080")

# Test tokens from multi_tenant.yaml
TOKENS = {
    "production": "prod_token_abc123",
    "development": "dev_token_def456", 
    "partner": "partner_token_ghi789",
}


def make_request(token: str, messages: list[dict]) -> dict:
    """Make a request to ShieldFlow with the given token."""
    headers = {"Authorization": f"Bearer {token}"}
    
    with httpx.Client() as client:
        response = client.post(
            f"{PROXY_URL}/v1/chat/completions",
            headers=headers,
            json={
                "model": "gpt-4",
                "messages": messages,
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "exec",
                            "description": "Execute a shell command",
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "command": {"type": "string"}
                                },
                                "required": ["command"]
                            }
                        }
                    },
                    {
                        "type": "function", 
                        "function": {
                            "name": "web_search",
                            "description": "Search the web",
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "query": {"type": "string"}
                                },
                                "required": ["query"]
                            }
                        }
                    }
                ]
            },
            timeout=30.0
        )
        return response.json()


def demo():
    print("=" * 60)
    print("ShieldFlow Multi-Tenant Demo")
    print("=" * 60)
    
    messages = [
        {"role": "user", "content": "Search for weather in Sydney"}
    ]
    
    # Test each tenant
    for tenant_name, token in TOKENS.items():
        print(f"\n--- {tenant_name.upper()} Tenant ---")
        print(f"Token: {token[:10]}...")
        
        try:
            result = make_request(token, messages)
            
            # Check for tool calls in response
            if "choices" in result and result["choices"]:
                choice = result["choices"][0]
                if "message" in choice:
                    msg = choice["message"]
                    if "tool_calls" in msg:
                        print(f"Tool calls allowed: {len(msg['tool_calls'])}")
                        for tc in msg["tool_calls"]:
                            print(f"  - {tc['function']['name']}")
                    elif "content" in msg:
                        print(f"Response: {msg['content'][:100]}...")
            
            # Check custom headers for tenant info
            # (would need to inspect response headers in production)
            print(f"✓ Request completed")
            
        except Exception as e:
            print(f"✗ Error: {e}")
    
    print("\n" + "=" * 60)
    print("Demo complete!")
    print("\nKey differences per tenant:")
    print("  - Production: strictest policy, exec blocked")
    print("  - Development: permissive, exec allowed for users")
    print("  - Partner: tool allowlist, web_search allowed")


if __name__ == "__main__":
    demo()
