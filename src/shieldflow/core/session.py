"""Secure session management.

A SecureSession ties together signing, context building, and validation
for a single user session.
"""

from __future__ import annotations

from typing import Any

from shieldflow.core.context import SecureContext
from shieldflow.core.policy import PolicyEngine
from shieldflow.core.signing import SessionSigner, create_session_signer
from shieldflow.core.trust import TrustLevel, owner_trust, user_trust
from shieldflow.core.validator import ActionValidator, ToolCall, ValidationResult


class SecureSession:
    """A trust-aware session for interacting with an LLM.

    Manages instruction signing, context building, and action validation
    for a single user session.
    """

    def __init__(
        self,
        signing_key: bytes | None = None,
        policy: PolicyEngine | None = None,
        trust_level: TrustLevel = TrustLevel.OWNER,
    ) -> None:
        self._signer = SessionSigner(key=signing_key) if signing_key else create_session_signer()
        self._policy = policy or PolicyEngine()
        self._validator = ActionValidator(self._policy)
        self._trust_level = trust_level
        self._context = SecureContext()

    @property
    def context(self) -> SecureContext:
        """The current secure context."""
        return self._context

    @property
    def signer(self) -> SessionSigner:
        """The session signer."""
        return self._signer

    def add_instruction(self, content: str, **metadata: Any) -> str:
        """Add a signed instruction from the session owner.

        The instruction is automatically signed with the session key
        and tagged with the session's trust level.
        """
        signed = self._signer.sign(content)
        trust = (
            owner_trust(verified_by="hmac")
            if self._trust_level == TrustLevel.OWNER
            else (user_trust(verified_by="hmac"))
        )
        return self._context.add_instruction(
            content=content,
            trust=trust,
            signature=signed.signature,
            **metadata,
        )

    def add_system(self, content: str, **metadata: Any) -> str:
        """Add a system-level instruction."""
        return self._context.add_system(content, **metadata)

    def add_data(
        self,
        content: str,
        source: str,
        trust: TrustLevel | str = TrustLevel.NONE,
        **metadata: Any,
    ) -> str:
        """Add external data to the context (untrusted by default)."""
        return self._context.add_data(
            content=content,
            source=source,
            trust=trust,
            **metadata,
        )

    def add_tool_result(
        self,
        content: str,
        tool_name: str,
        tool_call_id: str | None = None,
        **metadata: Any,
    ) -> str:
        """Add a tool result to the context."""
        return self._context.add_tool_result(
            content=content,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            **metadata,
        )

    def to_messages(self) -> list[dict[str, Any]]:
        """Get OpenAI-compatible messages with trust enforcement."""
        return self._context.to_messages()

    def validate_action(self, tool_call: ToolCall) -> ValidationResult:
        """Validate a tool call against trust policies."""
        return self._validator.validate(tool_call, self._context)

    def validate_actions(self, tool_calls: list[ToolCall]) -> list[ValidationResult]:
        """Validate multiple tool calls."""
        return self._validator.validate_batch(tool_calls, self._context)

    def new_context(self) -> None:
        """Reset the context for a new conversation turn."""
        self._context = SecureContext()
