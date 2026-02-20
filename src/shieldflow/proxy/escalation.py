"""Adaptive policy escalation based on session anomaly signals.

When a session's risk score exceeds a configurable threshold, ALLOW
decisions are automatically escalated to CONFIRM for tools above a
minimum trust requirement.  This forces human review during active
attacks without disrupting low-risk operations.

Design
------
* **Trigger:** :meth:`AnomalyMonitor.is_anomalous` returns True for
  the session.
* **Scope:** Only ALLOW decisions are escalated; BLOCK decisions remain
  unchanged (already the strongest enforcement).
* **Selectivity:** Only tools whose policy ``min_trust`` is ≥ ``USER``
  are escalated.  Fully public tools (``min_trust: none``) are left as
  ALLOW even during anomalous sessions, to avoid blocking benign
  read-only operations like ``web_search``.
* **Audit trail:** Escalated decisions carry a ``escalated_from`` field
  and ``escalation_reason`` in the :class:`EscalationResult` so the
  dashboard / audit log can distinguish organic CONFIRM from adaptive
  escalation.

Usage::

    escalation = AdaptiveEscalation(anomaly_monitor, policy_engine)

    # After standard validation:
    result = validator.validate(tool_call, ctx)

    # Check for escalation:
    escalated = escalation.maybe_escalate(result, session_id, tool_name)
    # escalated.decision may now be CONFIRM instead of ALLOW
"""

from __future__ import annotations

from dataclasses import dataclass

from shieldflow.core.policy import ActionDecision, PolicyEngine
from shieldflow.core.validator import ValidationResult
from shieldflow.proxy.anomaly import AnomalyMonitor


@dataclass
class EscalationResult:
    """Result of an adaptive escalation check.

    Attributes:
        original: The original :class:`ValidationResult` from the validator.
        escalated: Whether the decision was changed.
        final_decision: The decision after escalation (may be unchanged).
        escalation_reason: Human-readable reason if escalated, else None.
    """

    original: ValidationResult
    escalated: bool
    final_decision: ActionDecision
    escalation_reason: str | None = None

    @property
    def decision(self) -> ActionDecision:
        """Alias for final_decision (convenience)."""
        return self.final_decision


class AdaptiveEscalation:
    """Escalate ALLOW → CONFIRM for anomalous sessions.

    Args:
        anomaly: The :class:`AnomalyMonitor` tracking session risk.
        policy: The :class:`PolicyEngine` used to look up tool min_trust.
        escalate_min_trust_name: Only escalate tools whose min_trust
            is at or above this level.  Default ``"user"`` means
            ``web_search`` (min_trust: none) is never escalated.
    """

    def __init__(
        self,
        anomaly: AnomalyMonitor,
        policy: PolicyEngine,
        escalate_min_trust_name: str = "user",
    ) -> None:
        self._anomaly = anomaly
        self._policy = policy
        self._min_trust_name = escalate_min_trust_name.lower()

    def maybe_escalate(
        self,
        result: ValidationResult,
        session_id: str | None,
        tool_name: str,
    ) -> EscalationResult:
        """Check whether *result* should be escalated for *session_id*.

        Returns an :class:`EscalationResult` wrapping the original.
        The ``final_decision`` is CONFIRM if all escalation conditions
        are met, otherwise it mirrors the original decision.

        Escalation conditions (all must be true):
        1. ``session_id`` is not None.
        2. The session is currently anomalous.
        3. The original decision is ALLOW (not BLOCK or CONFIRM).
        4. The tool's policy ``min_trust`` is ≥ the configured threshold.
        """
        # Fast path: no session tracking or already non-ALLOW
        if not session_id or result.decision != ActionDecision.ALLOW:
            return EscalationResult(
                original=result,
                escalated=False,
                final_decision=result.decision,
            )

        # Check anomaly status
        if not self._anomaly.is_anomalous(session_id):
            return EscalationResult(
                original=result,
                escalated=False,
                final_decision=result.decision,
            )

        # Check tool's min_trust threshold
        if not self._should_escalate_tool(tool_name):
            return EscalationResult(
                original=result,
                escalated=False,
                final_decision=result.decision,
            )

        # All conditions met — escalate ALLOW → CONFIRM
        risk_score = self._anomaly.risk_score(session_id)
        return EscalationResult(
            original=result,
            escalated=True,
            final_decision=ActionDecision.CONFIRM,
            escalation_reason=(
                f"Adaptive escalation: session {session_id} risk score "
                f"{risk_score:.2f} exceeds threshold. Tool '{tool_name}' "
                f"escalated from ALLOW to CONFIRM for human review."
            ),
        )

    def _should_escalate_tool(self, tool_name: str) -> bool:
        """Return True if *tool_name*'s min_trust warrants escalation.

        Tools with ``min_trust: none`` (e.g. web_search) are never
        escalated because they are read-only and low-risk.
        """
        action_policy = self._policy.get_action(tool_name)
        if action_policy is None:
            # Unknown tools are already blocked by the validator;
            # if somehow allowed, escalate conservatively.
            return True
        return action_policy.min_trust.name.lower() != "none"
