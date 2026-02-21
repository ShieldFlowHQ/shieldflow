"""Secure session management.

A SecureSession ties together signing, context building, and validation
for a single user session.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from shieldflow.core.context import SecureContext
from shieldflow.core.policy import PolicyEngine
from shieldflow.core.signing import SessionSigner, create_session_signer
from shieldflow.core.trust import TrustLevel, owner_trust, user_trust
from shieldflow.core.validator import ActionValidator, ToolCall, ValidationResult


# Default maximum session duration (seconds)
# Sessions older than this will be considered expired
DEFAULT_MAX_SESSION_DURATION_SECONDS = 3600  # 1 hour

# Default key rotation interval (seconds)
# After this duration, a new key is generated for the session
DEFAULT_KEY_ROTATION_INTERVAL_SECONDS = 1800  # 30 minutes


class SessionExpiryError(Exception):
    """Raised when a session has expired."""
    pass


class KeyRotationReason(Enum):
    """Reason for key rotation."""
    SCHEDULED = "scheduled"  # Regular rotation interval
    EXPIRED = "expired"  # Session expired, creating new context


class SecureSession:
    """A trust-aware session for interacting with an LLM.

    Manages instruction signing, context building, and action validation
    for a single user session.

    Attributes:
        max_session_duration_seconds: Maximum age before session is considered
            expired. Default: 1 hour.
        key_rotation_interval_seconds: Interval for rotating the signing key.
            Default: 30 minutes. Set to 0 to disable rotation.
    """

    def __init__(
        self,
        signing_key: bytes | None = None,
        policy: PolicyEngine | None = None,
        trust_level: TrustLevel = TrustLevel.OWNER,
        max_session_duration_seconds: int = DEFAULT_MAX_SESSION_DURATION_SECONDS,
        key_rotation_interval_seconds: int = DEFAULT_KEY_ROTATION_INTERVAL_SECONDS,
    ) -> None:
        self._signer = SessionSigner(key=signing_key) if signing_key else create_session_signer()
        self._policy = policy or PolicyEngine()
        self._validator = ActionValidator(self._policy)
        self._trust_level = trust_level
        self._context = SecureContext()
        self._created_at = time.time()
        self._last_rotation_at = self._created_at
        self._max_session_duration = max_session_duration_seconds
        self._key_rotation_interval = key_rotation_interval_seconds

    @property
    def created_at(self) -> float:
        """Unix timestamp when the session was created."""
        return self._created_at

    @property
    def age_seconds(self) -> float:
        """Current age of the session in seconds."""
        return time.time() - self._created_at

    @property
    def is_expired(self) -> bool:
        """Check if the session has exceeded its maximum duration."""
        return self.age_seconds > self._max_session_duration

    @property
    def key_id(self) -> str:
        """Current signing key identifier."""
        return self._signer.key_id

    def _check_and_rotate_if_needed(self) -> None:
        """Check if key rotation is needed and rotate if so."""
        if self._key_rotation_interval <= 0:
            return

        if time.time() - self._last_rotation_at >= self._key_rotation_interval:
            self._rotate_key(KeyRotationReason.SCHEDULED)

    def _rotate_key(self, reason: KeyRotationReason) -> None:
        """Rotate the signing key with a new ephemeral key.

        Args:
            reason: Reason for key rotation.
        """
        self._signer = create_session_signer()
        self._last_rotation_at = time.time()

    def _ensure_valid_session(self) -> None:
        """Ensure the session is still valid, raising if expired."""
        if self.is_expired:
            raise SessionExpiryError(
                f"Session expired after {self.age_seconds:.1f}s "
                f"(max {self._max_session_duration}s)"
            )
        self._check_and_rotate_if_needed()

    def rotate_key(self) -> str:
        """Manually rotate the session signing key.

        Returns:
            The new key ID after rotation.

        Raises:
            SessionExpiryError: If the session has expired.
        """
        self._ensure_valid_session()
        old_key_id = self._signer.key_id
        self._rotate_key(KeyRotationReason.SCHEDULED)
        return self._signer.key_id

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

        Raises:
            SessionExpiryError: If the session has expired.
        """
        self._ensure_valid_session()
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
        """Add a system-level instruction.

        Raises:
            SessionExpiryError: If the session has expired.
        """
        self._ensure_valid_session()
        return self._context.add_system(content, **metadata)

    def add_data(
        self,
        content: str,
        source: str,
        trust: TrustLevel | str = TrustLevel.NONE,
        **metadata: Any,
    ) -> str:
        """Add external data to the context (untrusted by default).

        Raises:
            SessionExpiryError: If the session has expired.
        """
        self._ensure_valid_session()
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
        """Add a tool result to the context.

        Raises:
            SessionExpiryError: If the session has expired.
        """
        self._ensure_valid_session()
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
        """Reset the context for a new conversation turn.

        Raises:
            SessionExpiryError: If the session has expired.
        """
        self._ensure_valid_session()
        self._context = SecureContext()
