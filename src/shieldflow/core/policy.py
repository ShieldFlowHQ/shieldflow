"""Policy engine for trust-gated action control.

The PolicyEngine evaluates whether a given action should be allowed
based on the trust level of the instruction that triggered it and
the configured action policies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

import yaml

from shieldflow.core.trust import TrustLevel


class ActionDecision(Enum):
    """Possible decisions for an action request."""

    ALLOW = "allow"
    BLOCK = "block"
    CONFIRM = "confirm"  # Requires explicit user approval


@dataclass(frozen=True)
class ActionPolicy:
    """Policy for a specific action type."""

    action: str
    min_trust: TrustLevel
    confirm_if_elevated: bool = False  # Extra check if trust was elevated
    never_auto: bool = False  # Always requires per-instance confirmation
    description: str = ""


@dataclass(frozen=True)
class ElevationRule:
    """Rule for elevating trust from a specific source."""

    source_type: str  # e.g., "email"
    match: dict[str, str] = field(default_factory=dict)  # e.g., {"from": "boss@co.com"}
    require_dkim: bool = False
    require_spf: bool = False
    elevate_to: TrustLevel = TrustLevel.USER
    allowed_actions: list[str] = field(default_factory=list)
    denied_actions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DataClass:
    """Classification for a type of data."""

    name: str
    patterns: list[str] = field(default_factory=list)
    external_share: ActionDecision = ActionDecision.BLOCK


@dataclass(frozen=True)
class PolicyDecision:
    """Result of a policy evaluation."""

    decision: ActionDecision
    action: str
    required_trust: TrustLevel
    actual_trust: TrustLevel
    reason: str
    data_classification: str | None = None
    provenance_source: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == ActionDecision.ALLOW

    @property
    def blocked(self) -> bool:
        return self.decision == ActionDecision.BLOCK


# Default action policies — secure by default
DEFAULT_ACTION_POLICIES: list[ActionPolicy] = [
    # Low risk — any trust level
    ActionPolicy("web_search", TrustLevel.NONE, description="Search the web"),
    ActionPolicy("web_fetch", TrustLevel.NONE, description="Fetch a URL"),
    ActionPolicy("summarise", TrustLevel.NONE, description="Summarise content"),
    ActionPolicy("read_public", TrustLevel.NONE, description="Read public data"),
    # Medium risk — requires user trust
    ActionPolicy("message.send", TrustLevel.USER, description="Send a message"),
    ActionPolicy("email.send", TrustLevel.USER, description="Send an email"),
    ActionPolicy("email.reply", TrustLevel.USER, description="Reply to an email"),
    ActionPolicy("file.read", TrustLevel.USER, description="Read a file"),
    ActionPolicy("file.write", TrustLevel.USER, description="Write a file"),
    ActionPolicy("calendar.update", TrustLevel.USER, description="Update calendar"),
    # High risk — requires owner trust
    ActionPolicy("exec", TrustLevel.OWNER, description="Execute code/commands"),
    ActionPolicy("file.delete", TrustLevel.OWNER, description="Delete a file"),
    ActionPolicy("config.modify", TrustLevel.OWNER, description="Modify configuration"),
    ActionPolicy("share.external", TrustLevel.OWNER, description="Share data externally"),
    # Never auto-approve
    ActionPolicy(
        "data.bulk_export",
        TrustLevel.OWNER,
        never_auto=True,
        description="Export data in bulk",
    ),
    ActionPolicy(
        "credential.read",
        TrustLevel.OWNER,
        never_auto=True,
        description="Access credentials",
    ),
    ActionPolicy(
        "send.new_recipient",
        TrustLevel.OWNER,
        never_auto=True,
        description="Send to new/unknown recipient",
    ),
]

DEFAULT_DATA_CLASSES: list[DataClass] = [
    DataClass(
        "restricted",
        patterns=[
            r"password\s*[:=]",
            r"api[_\-]?key\s*[:=]",
            r"-----BEGIN .* KEY-----",
            r"sk-[a-zA-Z0-9]{32,}",
            r"\b\d{3}-\d{2}-\d{4}\b",
        ],
        external_share=ActionDecision.BLOCK,
    ),
    DataClass(
        "internal",
        patterns=[
            r"employee|staff\s+list|personnel",
            r"client\s+list|customer\s+list",
            r"salary|compensation|payroll",
        ],
        external_share=ActionDecision.CONFIRM,
    ),
    DataClass(
        "public",
        patterns=[],
        external_share=ActionDecision.ALLOW,
    ),
]


class PolicyEngine:
    """Evaluates actions against trust policies.

    The engine checks:
    1. Does the action's trigger source meet the minimum trust requirement?
    2. Does the data being acted on allow the intended operation?
    3. Are there any never-auto rules that require confirmation?
    """

    def __init__(
        self,
        action_policies: list[ActionPolicy] | None = None,
        elevation_rules: list[ElevationRule] | None = None,
        data_classes: list[DataClass] | None = None,
    ) -> None:
        self._action_policies: dict[str, ActionPolicy] = {}
        for policy in action_policies or DEFAULT_ACTION_POLICIES:
            self._action_policies[policy.action] = policy

        self._elevation_rules = elevation_rules or []
        self._data_classes = data_classes or DEFAULT_DATA_CLASSES

    @classmethod
    def from_yaml(cls, path: str) -> PolicyEngine:
        """Load policy engine from a YAML config file."""
        with open(path) as f:
            config = yaml.safe_load(f)

        action_policies = []
        for action, spec in config.get("actions", {}).items():
            action_policies.append(
                ActionPolicy(
                    action=action,
                    min_trust=TrustLevel.from_string(spec.get("min_trust", "owner")),
                    never_auto=spec.get("never_auto", False),
                    confirm_if_elevated=spec.get("confirm_if_elevated", False),
                    description=spec.get("description", ""),
                )
            )

        elevation_rules = []
        for rule in config.get("elevation_rules", []):
            elevation_rules.append(
                ElevationRule(
                    source_type=rule["source"],
                    match=rule.get("match", {}),
                    require_dkim=rule.get("require_dkim", False),
                    require_spf=rule.get("require_spf", False),
                    elevate_to=TrustLevel.from_string(rule.get("elevate_to", "user")),
                    allowed_actions=rule.get("allowed_actions", []),
                    denied_actions=rule.get("denied_actions", []),
                )
            )

        data_classes = []
        for dc in config.get("data_classification", []):
            data_classes.append(
                DataClass(
                    name=dc["name"],
                    patterns=dc.get("patterns", []),
                    external_share=ActionDecision(dc.get("external_share", "block")),
                )
            )

        return cls(
            action_policies=action_policies or None,
            elevation_rules=elevation_rules or None,
            data_classes=data_classes or None,
        )

    def evaluate(
        self,
        action: str,
        trigger_trust: TrustLevel,
        data_content: str | None = None,
        is_external_destination: bool = False,
        trigger_source: str | None = None,
    ) -> PolicyDecision:
        """Evaluate whether an action should be allowed.

        Args:
            action: The action type (e.g., "message.send", "exec").
            trigger_trust: Trust level of the content that triggered this action.
            data_content: Content being sent/shared (for data classification).
            is_external_destination: Whether the action sends data externally.
            trigger_source: Description of what triggered this action.

        Returns:
            PolicyDecision with allow/block/confirm and reasoning.
        """
        # Look up action policy
        policy = self._get_policy(action)

        # Check trust requirement
        if not trigger_trust.meets_requirement(policy.min_trust):
            return PolicyDecision(
                decision=ActionDecision.BLOCK,
                action=action,
                required_trust=policy.min_trust,
                actual_trust=trigger_trust,
                reason=(
                    f"Action '{action}' requires trust level {policy.min_trust.name} "
                    f"but was triggered by source with trust level {trigger_trust.name}"
                ),
                provenance_source=trigger_source,
            )

        # Check never-auto
        if policy.never_auto:
            return PolicyDecision(
                decision=ActionDecision.CONFIRM,
                action=action,
                required_trust=policy.min_trust,
                actual_trust=trigger_trust,
                reason=f"Action '{action}' requires explicit per-instance approval",
                provenance_source=trigger_source,
            )

        # Check data classification if sending externally
        if data_content and is_external_destination:
            data_class = self._classify_data(data_content)
            if data_class:
                share_decision = data_class.external_share
                if share_decision == ActionDecision.BLOCK:
                    return PolicyDecision(
                        decision=ActionDecision.BLOCK,
                        action=action,
                        required_trust=policy.min_trust,
                        actual_trust=trigger_trust,
                        reason=(
                            f"Data classified as '{data_class.name}' cannot be shared externally"
                        ),
                        data_classification=data_class.name,
                        provenance_source=trigger_source,
                    )
                if share_decision == ActionDecision.CONFIRM:
                    return PolicyDecision(
                        decision=ActionDecision.CONFIRM,
                        action=action,
                        required_trust=policy.min_trust,
                        actual_trust=trigger_trust,
                        reason=(
                            f"Data classified as '{data_class.name}' "
                            f"requires confirmation before external sharing"
                        ),
                        data_classification=data_class.name,
                        provenance_source=trigger_source,
                    )

        # All checks passed
        return PolicyDecision(
            decision=ActionDecision.ALLOW,
            action=action,
            required_trust=policy.min_trust,
            actual_trust=trigger_trust,
            reason="Action allowed by policy",
            provenance_source=trigger_source,
        )

    def _get_policy(self, action: str) -> ActionPolicy:
        """Get the policy for an action, falling back to strict defaults."""
        if action in self._action_policies:
            return self._action_policies[action]

        # Check for wildcard/prefix matches
        parts = action.split(".")
        for i in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:i]) + ".*"
            if prefix in self._action_policies:
                return self._action_policies[prefix]

        # Default: require OWNER trust for unknown actions (fail secure)
        return ActionPolicy(
            action=action,
            min_trust=TrustLevel.OWNER,
            description="Unknown action (default: owner-only)",
        )

    def _classify_data(self, content: str) -> DataClass | None:
        """Classify data content, returning the most restrictive match."""
        for data_class in self._data_classes:
            for pattern in data_class.patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return data_class
        return None
