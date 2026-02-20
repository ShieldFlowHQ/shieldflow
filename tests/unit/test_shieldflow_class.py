"""Tests for the ShieldFlow main class (Phase D.1 coverage: 49% → 90%+)."""

from __future__ import annotations

from typing import Any

import pytest

from shieldflow.core.context import SecureContext
from shieldflow.core.policy import PolicyEngine
from shieldflow.core.session import SecureSession
from shieldflow.core.trust import TrustLevel
from shieldflow.core.validator import ToolCall
from shieldflow.shieldflow import ShieldFlow


class TestShieldFlowInit:
    def test_default_init(self) -> None:
        sf = ShieldFlow()
        assert isinstance(sf.policy, PolicyEngine)

    def test_init_with_dict_config(self) -> None:
        sf = ShieldFlow(config={"actions": {}})
        assert isinstance(sf.policy, PolicyEngine)

    def test_init_with_custom_policy(self) -> None:
        policy = PolicyEngine()
        sf = ShieldFlow(policy=policy)
        assert sf.policy is policy

    def test_init_with_dict_and_custom_policy(self) -> None:
        policy = PolicyEngine()
        sf = ShieldFlow(config={"key": "val"}, policy=policy)
        assert sf.policy is policy

    def test_init_with_yaml_file(self, tmp_path: Any) -> None:
        cfg = tmp_path / "config.yaml"
        cfg.write_text("version: '1'\n")
        sf = ShieldFlow(config=str(cfg))
        assert isinstance(sf.policy, PolicyEngine)

    def test_init_with_path_object(self, tmp_path: Any) -> None:
        cfg = tmp_path / "config.yaml"
        cfg.write_text("version: '1'\n")
        sf = ShieldFlow(config=cfg)
        assert isinstance(sf.policy, PolicyEngine)

    def test_init_with_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            ShieldFlow(config="/nonexistent/path.yaml")

    def test_init_with_none_config(self) -> None:
        sf = ShieldFlow(config=None)
        assert isinstance(sf.policy, PolicyEngine)


class TestCreateSession:
    def test_returns_secure_session(self) -> None:
        sf = ShieldFlow()
        session = sf.create_session()
        assert isinstance(session, SecureSession)

    def test_custom_trust_level(self) -> None:
        sf = ShieldFlow()
        session = sf.create_session(trust_level=TrustLevel.USER)
        bid = session.add_instruction("test")
        block = session.context.get_block(bid)
        assert block is not None
        assert block.trust.level == TrustLevel.USER

    def test_custom_signing_key(self) -> None:
        sf = ShieldFlow()
        key = b"my-custom-key-32-bytes-long!!!!!"
        session = sf.create_session(signing_key=key)
        assert session.signer is not None


class TestCreateContext:
    def test_returns_secure_context(self) -> None:
        sf = ShieldFlow()
        ctx = sf.create_context()
        assert isinstance(ctx, SecureContext)


class TestValidateAction:
    def test_validate_allowed(self) -> None:
        sf = ShieldFlow()
        ctx = SecureContext()
        ctx.add_instruction("Send a message")
        tc = ToolCall(id="c1", name="message.send", arguments={"to": "team"})
        result = sf.validate_action(tc, ctx)
        assert result.allowed

    def test_validate_blocked(self) -> None:
        sf = ShieldFlow()
        ctx = SecureContext()
        ctx.add_data("evil", source="web", trust=TrustLevel.NONE)
        tc = ToolCall(id="c2", name="exec", arguments={"cmd": "rm -rf /"})
        result = sf.validate_action(tc, ctx)
        assert result.blocked


class TestValidateActions:
    def test_batch_returns_list(self) -> None:
        sf = ShieldFlow()
        ctx = SecureContext()
        ctx.add_instruction("Do things")
        calls = [
            ToolCall(id="c1", name="message.send", arguments={"to": "a"}),
            ToolCall(id="c2", name="message.send", arguments={"to": "b"}),
        ]
        results = sf.validate_actions(calls, ctx)
        assert len(results) == 2
