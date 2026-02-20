"""Coverage tests for SecureContext serialization paths (Phase D.1).

Targets context.py coverage from 74% → 90%+.
Covers: to_messages(), _trust_preamble(), _wrap_untrusted(),
add_data() trust type branching, get_block(), get_untrusted_blocks(),
get_instruction_blocks().
"""

from __future__ import annotations

from shieldflow.core.context import SecureContext
from shieldflow.core.trust import TrustLevel, TrustTag


class TestToMessages:
    def test_empty_context_returns_preamble_only(self) -> None:
        ctx = SecureContext()
        msgs = ctx.to_messages()
        assert len(msgs) == 1
        assert msgs[0]["role"] == "system"

    def test_preamble_can_be_disabled(self) -> None:
        ctx = SecureContext()
        msgs = ctx.to_messages(include_trust_preamble=False)
        assert len(msgs) == 0

    def test_instruction_serialized_as_user_message(self) -> None:
        ctx = SecureContext()
        ctx.add_instruction("Hello world")
        msgs = ctx.to_messages(include_trust_preamble=False)
        assert len(msgs) == 1
        assert msgs[0]["role"] == "user"
        assert "Hello world" in msgs[0]["content"]

    def test_system_message_serialized(self) -> None:
        ctx = SecureContext()
        ctx.add_system("You are a helpful assistant")
        msgs = ctx.to_messages(include_trust_preamble=False)
        assert len(msgs) == 1
        assert msgs[0]["role"] == "system"
        assert "helpful assistant" in msgs[0]["content"]

    def test_untrusted_data_wrapped_in_isolation(self) -> None:
        ctx = SecureContext()
        ctx.add_data("Evil payload", source="web_fetch", trust=TrustLevel.NONE)
        msgs = ctx.to_messages(include_trust_preamble=False)
        assert len(msgs) == 1
        # Untrusted content should be wrapped in isolation markers
        content = msgs[0]["content"]
        assert "EXTERNAL" in content or "UNTRUSTED" in content

    def test_trusted_data_not_wrapped(self) -> None:
        ctx = SecureContext()
        ctx.add_instruction("Safe content")
        msgs = ctx.to_messages(include_trust_preamble=False)
        content = msgs[0]["content"]
        # OWNER-trust instructions should not be wrapped with EXTERNAL markers
        assert "EXTERNAL_DATA" not in content

    def test_tool_result_with_call_id_serialized(self) -> None:
        ctx = SecureContext()
        ctx.add_tool_result(
            "Result",
            tool_name="search",
            tool_call_id="call_123",
        )
        msgs = ctx.to_messages(include_trust_preamble=False)
        assert len(msgs) == 1
        assert msgs[0]["role"] == "tool"
        assert msgs[0]["tool_call_id"] == "call_123"

    def test_tool_result_without_call_id_no_key(self) -> None:
        ctx = SecureContext()
        ctx.add_tool_result("Result", tool_name="search")
        msgs = ctx.to_messages(include_trust_preamble=False)
        assert len(msgs) == 1
        assert "tool_call_id" not in msgs[0]

    def test_multiple_blocks_in_order(self) -> None:
        ctx = SecureContext()
        ctx.add_system("System prompt")
        ctx.add_instruction("User instruction")
        ctx.add_data("Web data", source="fetch", trust=TrustLevel.NONE)
        ctx.add_tool_result("Tool output", tool_name="search")
        msgs = ctx.to_messages(include_trust_preamble=False)
        assert len(msgs) == 4
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"
        assert msgs[2]["role"] == "user"  # data defaults to user role
        assert msgs[3]["role"] == "tool"

    def test_preamble_content_mentions_security(self) -> None:
        ctx = SecureContext()
        msgs = ctx.to_messages(include_trust_preamble=True)
        preamble = msgs[0]["content"]
        assert "SECURITY" in preamble
        assert "VERIFIED_INSTRUCTION" in preamble
        assert "EXTERNAL_DATA" in preamble
        assert "injection" in preamble.lower()


class TestAddDataTrustBranching:
    """Cover the three branches in add_data() trust parameter handling."""

    def test_string_trust_parameter(self) -> None:
        ctx = SecureContext()
        bid = ctx.add_data("Data", source="s3", trust="tool")
        block = ctx.get_block(bid)
        assert block is not None
        assert block.trust.level == TrustLevel.TOOL

    def test_trust_level_enum_parameter(self) -> None:
        ctx = SecureContext()
        bid = ctx.add_data("Data", source="api", trust=TrustLevel.AGENT)
        block = ctx.get_block(bid)
        assert block is not None
        assert block.trust.level == TrustLevel.AGENT

    def test_trust_tag_parameter(self) -> None:
        tag = TrustTag(level=TrustLevel.SYSTEM, source="internal_api")
        ctx = SecureContext()
        bid = ctx.add_data("Data", source="internal", trust=tag)
        block = ctx.get_block(bid)
        assert block is not None
        assert block.trust.level == TrustLevel.SYSTEM
        assert block.trust.source == "internal_api"


class TestGetBlock:
    def test_get_existing_block(self) -> None:
        ctx = SecureContext()
        bid = ctx.add_instruction("Test")
        block = ctx.get_block(bid)
        assert block is not None
        assert block.block_id == bid

    def test_get_nonexistent_block_returns_none(self) -> None:
        ctx = SecureContext()
        assert ctx.get_block("nonexistent-id") is None


class TestGetUntrustedBlocks:
    def test_returns_only_untrusted(self) -> None:
        ctx = SecureContext()
        ctx.add_instruction("Trusted")
        ctx.add_data("Untrusted", source="web", trust=TrustLevel.NONE)
        untrusted = ctx.get_untrusted_blocks()
        assert len(untrusted) == 1
        assert untrusted[0].trust.level == TrustLevel.NONE

    def test_empty_when_no_untrusted(self) -> None:
        ctx = SecureContext()
        ctx.add_instruction("Only trusted")
        assert len(ctx.get_untrusted_blocks()) == 0


class TestGetInstructionBlocks:
    def test_returns_instruction_blocks(self) -> None:
        ctx = SecureContext()
        ctx.add_instruction("Instruction 1")
        ctx.add_instruction("Instruction 2")
        ctx.add_data("Data", source="web", trust=TrustLevel.NONE)
        instructions = ctx.get_instruction_blocks()
        assert len(instructions) == 2

    def test_system_messages_not_instructions(self) -> None:
        """System messages are not returned by get_instruction_blocks()."""
        ctx = SecureContext()
        ctx.add_system("System prompt")
        instructions = ctx.get_instruction_blocks()
        assert len(instructions) == 0
