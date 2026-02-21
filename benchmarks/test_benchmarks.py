"""Performance benchmarks for ShieldFlow core components.

Run with: python -m pytest benchmarks/ -v
"""

import pytest
import time
from shieldflow.core.policy import PolicyEngine
from shieldflow.core.validator import ActionValidator
from shieldflow.core.trust import TrustLevel


class BenchmarkPolicyEngine:
    """Benchmarks for PolicyEngine."""

    @pytest.fixture
    def policy(self):
        return PolicyEngine()

    def test_policy_load(self, benchmark):
        """Benchmark policy loading."""
        result = benchmark(PolicyEngine)
        assert result is not None

    def test_match_rule(self, policy, benchmark):
        """Benchmark rule matching."""
        tool_name = "exec"
        
        def match():
            return policy.match_action(tool_name, TrustLevel.USER)
        
        result = benchmark(match)
        assert result is not None


class BenchmarkValidator:
    """Benchmarks for ActionValidator."""

    @pytest.fixture
    def validator(self):
        return ActionValidator(PolicyEngine())

    def test_validate_allowed(self, validator, benchmark):
        """Benchmark validating an allowed action."""
        from shieldflow.core.context import SecureContext
        
        ctx = SecureContext(
            role="user",
            trust_level=TrustLevel.USER,
            can_instruct=True,
            data_classification=None,
        )
        
        tool_call = {
            "function": {
                "name": "web_search",
                "arguments": "{}"
            }
        }
        
        def validate():
            return validator.validate(tool_call, ctx)
        
        result = benchmark(validate)
        assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
