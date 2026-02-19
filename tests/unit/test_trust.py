"""Tests for the trust level system."""

import pytest

from shieldflow.core.trust import TrustLevel, TrustTag, owner_trust, untrusted, user_trust


class TestTrustLevel:
    def test_hierarchy_ordering(self):
        assert (
            TrustLevel.NONE
            < TrustLevel.TOOL
            < TrustLevel.AGENT
            < TrustLevel.SYSTEM
            < TrustLevel.USER
            < TrustLevel.OWNER
        )

    def test_meets_requirement(self):
        assert TrustLevel.OWNER.meets_requirement(TrustLevel.USER)
        assert TrustLevel.OWNER.meets_requirement(TrustLevel.OWNER)
        assert TrustLevel.USER.meets_requirement(TrustLevel.USER)
        assert not TrustLevel.NONE.meets_requirement(TrustLevel.USER)
        assert not TrustLevel.TOOL.meets_requirement(TrustLevel.USER)

    def test_from_string(self):
        assert TrustLevel.from_string("owner") == TrustLevel.OWNER
        assert TrustLevel.from_string("OWNER") == TrustLevel.OWNER
        assert TrustLevel.from_string("none") == TrustLevel.NONE
        assert TrustLevel.from_string("full") == TrustLevel.OWNER
        assert TrustLevel.from_string("any") == TrustLevel.NONE

    def test_from_string_invalid(self):
        with pytest.raises(ValueError, match="Unknown trust level"):
            TrustLevel.from_string("superadmin")


class TestTrustTag:
    def test_immutable(self):
        tag = owner_trust()
        with pytest.raises(AttributeError):
            tag.level = TrustLevel.NONE  # type: ignore

    def test_can_instruct(self):
        assert owner_trust().can_instruct is True
        assert user_trust().can_instruct is True
        assert untrusted("web").can_instruct is False
        assert TrustTag(level=TrustLevel.TOOL, source="api").can_instruct is False
        assert TrustTag(level=TrustLevel.AGENT, source="bot").can_instruct is False

    def test_is_trusted(self):
        assert owner_trust().is_trusted is True
        assert user_trust().is_trusted is True
        assert untrusted("web").is_trusted is False

    def test_elevation_tracking(self):
        tag = TrustTag(
            level=TrustLevel.USER,
            source="email",
            elevated_from=TrustLevel.NONE,
            elevation_reason="DKIM verified sender",
        )
        assert tag.was_elevated is True
        assert tag.elevated_from == TrustLevel.NONE

    def test_no_elevation(self):
        tag = owner_trust()
        assert tag.was_elevated is False
