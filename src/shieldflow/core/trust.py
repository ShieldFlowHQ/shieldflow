"""Trust level definitions and comparison logic."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class TrustLevel(IntEnum):
    """Trust levels form a strict hierarchy.

    Higher levels include all permissions of lower levels.
    Trust is assigned at ingestion and NEVER escalates through processing.
    """

    NONE = 0  # External/untrusted: web pages, emails, documents
    TOOL = 1  # Tool/API outputs: informational only
    AGENT = 2  # Other AI agents: scoped actions only
    SYSTEM = 3  # System-level: cron, scheduled tasks, system prompts
    USER = 4  # Authenticated users: most actions
    OWNER = 5  # Agent owner: full control

    @classmethod
    def from_string(cls, value: str) -> TrustLevel:
        """Parse a trust level from a string (case-insensitive)."""
        mapping = {
            "none": cls.NONE,
            "tool": cls.TOOL,
            "agent": cls.AGENT,
            "system": cls.SYSTEM,
            "user": cls.USER,
            "owner": cls.OWNER,
            "full": cls.OWNER,
            "any": cls.NONE,
        }
        normalised = value.strip().lower()
        if normalised not in mapping:
            raise ValueError(
                f"Unknown trust level: {value!r}. Valid levels: {', '.join(mapping.keys())}"
            )
        return mapping[normalised]

    def meets_requirement(self, required: TrustLevel) -> bool:
        """Check if this trust level meets or exceeds a requirement."""
        return self >= required


@dataclass(frozen=True)
class TrustTag:
    """Immutable trust metadata attached to a context block.

    Once assigned, a TrustTag cannot be modified — this is a core
    security invariant. Trust is set at ingestion and is final.
    """

    level: TrustLevel
    source: str  # e.g., "user_chat", "web_fetch", "email", "tool:web_search"
    source_id: str | None = None  # Unique ID for provenance tracking
    verified_by: str | None = None  # e.g., "hmac", "session_auth", "framework"
    elevated_from: TrustLevel | None = None  # If trust was elevated, original level
    elevation_reason: str | None = None  # Why trust was elevated

    @property
    def was_elevated(self) -> bool:
        """Whether this trust level was elevated from a lower level."""
        return self.elevated_from is not None

    @property
    def is_trusted(self) -> bool:
        """Whether this source is trusted enough to potentially instruct."""
        return self.level >= TrustLevel.USER

    @property
    def can_instruct(self) -> bool:
        """Whether this source is allowed to provide instructions.

        Only USER and above can instruct. TOOL, AGENT, and below
        are informational only.
        """
        return self.level >= TrustLevel.USER

    def __str__(self) -> str:
        # Use explicit None guard so mypy can narrow the type of elevated_from.
        if self.elevated_from is not None:
            elevated = f" (elevated from {self.elevated_from.name})"
        else:
            elevated = ""
        return f"TrustTag({self.level.name}, source={self.source}{elevated})"


# Convenience constructors for common trust tags
def owner_trust(source: str = "user_chat", verified_by: str = "hmac") -> TrustTag:
    """Create an OWNER-level trust tag."""
    return TrustTag(level=TrustLevel.OWNER, source=source, verified_by=verified_by)


def user_trust(source: str = "user_chat", verified_by: str = "hmac") -> TrustTag:
    """Create a USER-level trust tag."""
    return TrustTag(level=TrustLevel.USER, source=source, verified_by=verified_by)


def system_trust(source: str = "system_prompt") -> TrustTag:
    """Create a SYSTEM-level trust tag."""
    return TrustTag(level=TrustLevel.SYSTEM, source=source, verified_by="framework")


def untrusted(source: str = "unknown") -> TrustTag:
    """Create a NONE-level trust tag for external/untrusted content."""
    return TrustTag(level=TrustLevel.NONE, source=source)
