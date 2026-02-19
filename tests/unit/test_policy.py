"""Tests for the policy engine."""

from shieldflow.core.policy import ActionDecision, PolicyEngine
from shieldflow.core.trust import TrustLevel


class TestPolicyEngine:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_low_risk_action_any_trust(self):
        result = self.engine.evaluate("web_search", TrustLevel.NONE)
        assert result.allowed

    def test_medium_risk_blocks_untrusted(self):
        result = self.engine.evaluate("message.send", TrustLevel.NONE)
        assert result.blocked
        assert "trust level NONE" in result.reason

    def test_medium_risk_allows_user(self):
        result = self.engine.evaluate("message.send", TrustLevel.USER)
        assert result.allowed

    def test_high_risk_blocks_user(self):
        result = self.engine.evaluate("exec", TrustLevel.USER)
        assert result.blocked

    def test_high_risk_allows_owner(self):
        result = self.engine.evaluate("exec", TrustLevel.OWNER)
        assert result.allowed

    def test_never_auto_requires_confirmation(self):
        result = self.engine.evaluate("data.bulk_export", TrustLevel.OWNER)
        assert result.decision == ActionDecision.CONFIRM
        assert "explicit" in result.reason

    def test_unknown_action_defaults_to_owner(self):
        result = self.engine.evaluate("some.unknown.action", TrustLevel.USER)
        assert result.blocked
        assert result.required_trust == TrustLevel.OWNER

    def test_data_classification_blocks_restricted(self):
        result = self.engine.evaluate(
            "email.send",
            TrustLevel.OWNER,
            data_content="Here is my password: hunter2",
            is_external_destination=True,
        )
        assert result.blocked
        assert result.data_classification == "restricted"

    def test_data_classification_confirms_internal(self):
        result = self.engine.evaluate(
            "email.send",
            TrustLevel.OWNER,
            data_content="Here is the staff list with all employee names",
            is_external_destination=True,
        )
        assert result.decision == ActionDecision.CONFIRM
        assert result.data_classification == "internal"

    def test_data_classification_allows_public(self):
        result = self.engine.evaluate(
            "email.send",
            TrustLevel.OWNER,
            data_content="Check out our latest blog post about AI",
            is_external_destination=True,
        )
        assert result.allowed

    def test_api_key_pattern_blocked(self):
        result = self.engine.evaluate(
            "email.send",
            TrustLevel.OWNER,
            data_content="The api_key is sk-abc123def456ghi789jkl012mno345pqr678",
            is_external_destination=True,
        )
        assert result.blocked
        assert result.data_classification == "restricted"

    def test_internal_data_ok_for_internal_destination(self):
        result = self.engine.evaluate(
            "email.send",
            TrustLevel.OWNER,
            data_content="Here is the staff list",
            is_external_destination=False,
        )
        assert result.allowed
