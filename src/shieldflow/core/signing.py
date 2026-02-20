"""HMAC-based instruction signing and verification.

This module implements the cryptographic foundation of ShieldFlow's trust model.
Instructions are signed at the transport layer using HMAC-SHA256, ensuring that
only holders of the session key can produce valid signatures.

Key security properties:
- Keys are ephemeral (per-session)
- Signatures are verified before content enters the context
- Constant-time comparison prevents timing attacks
- Timestamps prevent replay attacks
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass

# Maximum age of a signed message before it's considered expired (seconds)
DEFAULT_MAX_AGE_SECONDS = 300  # 5 minutes


@dataclass(frozen=True)
class SignedMessage:
    """A message with its HMAC signature and metadata."""

    content: str
    timestamp: float
    signature: str  # hex-encoded HMAC-SHA256
    key_id: str | None = None  # Identifies which key was used


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying a signed message."""

    valid: bool
    reason: str
    message: SignedMessage | None = None


class SessionSigner:
    """Manages HMAC signing for a single session.

    Each session gets an ephemeral key that is never stored in the
    context window or transmitted in message content.
    """

    def __init__(
        self,
        key: bytes | None = None,
        key_id: str | None = None,
        max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    ) -> None:
        """Initialise with an existing key or generate a new one.

        Args:
            key: 32-byte signing key. Generated if not provided.
            key_id: Optional identifier for this key.
            max_age_seconds: Maximum age of a valid signature.
        """
        self._key = key or os.urandom(32)
        self._key_id = key_id or self._derive_key_id()
        self._max_age = max_age_seconds

    @property
    def key_id(self) -> str:
        """Public identifier for this key (safe to share)."""
        return self._key_id

    def _derive_key_id(self) -> str:
        """Derive a non-secret identifier from the key."""
        return hashlib.sha256(b"shieldflow-key-id:" + self._key).hexdigest()[:16]

    def _compute_hmac(self, content: str, timestamp: float) -> str:
        """Compute HMAC-SHA256 over content and timestamp."""
        message = f"{timestamp}:{content}".encode()
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def sign(self, content: str) -> SignedMessage:
        """Sign a message with the session key.

        Args:
            content: The message content to sign.

        Returns:
            A SignedMessage with the content, timestamp, and signature.
        """
        timestamp = time.time()
        signature = self._compute_hmac(content, timestamp)
        return SignedMessage(
            content=content,
            timestamp=timestamp,
            signature=signature,
            key_id=self._key_id,
        )

    def verify(self, message: SignedMessage) -> VerificationResult:
        """Verify a signed message.

        Checks:
        1. Signature is valid (constant-time comparison)
        2. Message is not expired (replay protection)
        3. Key ID matches (if provided)

        Args:
            message: The signed message to verify.

        Returns:
            VerificationResult with validity and reason.
        """
        # Check key ID if provided
        if message.key_id is not None and message.key_id != self._key_id:
            return VerificationResult(
                valid=False,
                reason=f"Key ID mismatch: expected {self._key_id}, got {message.key_id}",
            )

        # Check timestamp (replay protection)
        age = time.time() - message.timestamp
        if age > self._max_age:
            return VerificationResult(
                valid=False,
                reason=f"Message expired: {age:.1f}s old (max {self._max_age}s)",
            )
        if age < -30:  # Allow 30s clock skew
            return VerificationResult(
                valid=False,
                reason=f"Message timestamp is in the future by {-age:.1f}s",
            )

        # Verify HMAC (constant-time comparison)
        expected = self._compute_hmac(message.content, message.timestamp)
        if not hmac.compare_digest(message.signature, expected):
            return VerificationResult(
                valid=False,
                reason="Invalid signature",
            )

        return VerificationResult(
            valid=True,
            reason="Signature valid",
            message=message,
        )


def create_session_signer() -> SessionSigner:
    """Create a new session signer with a random ephemeral key."""
    return SessionSigner()
