"""Main ShieldFlow class — the primary entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from shieldflow.core.context import SecureContext
from shieldflow.core.policy import PolicyEngine
from shieldflow.core.session import SecureSession
from shieldflow.core.trust import TrustLevel
from shieldflow.core.validator import ActionValidator, ToolCall, ValidationResult


class ShieldFlow:
    """Main entry point for ShieldFlow.

    Provides a high-level API for creating secure sessions,
    validating actions, and managing trust policies.
    """

    def __init__(
        self,
        config: str | Path | dict[str, Any] | None = None,
        policy: PolicyEngine | None = None,
    ) -> None:
        if isinstance(config, (str, Path)):
            config_path = Path(config)
            if config_path.exists():
                with open(config_path) as f:
                    self._config = yaml.safe_load(f) or {}
                self._policy = PolicyEngine.from_yaml(str(config_path))
            else:
                raise FileNotFoundError(f"Config file not found: {config_path}")
        elif isinstance(config, dict):
            self._config = config
            self._policy = policy or PolicyEngine()
        else:
            self._config = {}
            self._policy = policy or PolicyEngine()

        self._validator = ActionValidator(self._policy)

    @property
    def policy(self) -> PolicyEngine:
        """The policy engine."""
        return self._policy

    def create_session(
        self,
        signing_key: bytes | None = None,
        trust_level: TrustLevel = TrustLevel.OWNER,
    ) -> SecureSession:
        """Create a new secure session.

        Args:
            signing_key: Optional pre-shared signing key.
            trust_level: Trust level for the session owner.

        Returns:
            A new SecureSession with its own signing key and context.
        """
        return SecureSession(
            signing_key=signing_key,
            policy=self._policy,
            trust_level=trust_level,
        )

    def create_context(self) -> SecureContext:
        """Create a new secure context (without a full session)."""
        return SecureContext()

    def validate_action(
        self,
        tool_call: ToolCall,
        context: SecureContext,
    ) -> ValidationResult:
        """Validate a single tool call against the context."""
        return self._validator.validate(tool_call, context)

    def validate_actions(
        self,
        tool_calls: list[ToolCall],
        context: SecureContext,
    ) -> list[ValidationResult]:
        """Validate multiple tool calls."""
        return self._validator.validate_batch(tool_calls, context)
