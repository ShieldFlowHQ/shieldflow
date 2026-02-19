"""Tests for HMAC signing and verification."""

import time

from shieldflow.core.signing import SessionSigner, SignedMessage, create_session_signer


class TestSessionSigner:
    def test_sign_and_verify(self):
        signer = create_session_signer()
        signed = signer.sign("Hello, world!")
        result = signer.verify(signed)
        assert result.valid is True

    def test_tampered_content_fails(self):
        signer = create_session_signer()
        signed = signer.sign("Hello, world!")
        tampered = SignedMessage(
            content="Hello, evil world!",
            timestamp=signed.timestamp,
            signature=signed.signature,
            key_id=signed.key_id,
        )
        result = signer.verify(tampered)
        assert result.valid is False
        assert "Invalid signature" in result.reason

    def test_wrong_key_fails(self):
        signer1 = create_session_signer()
        signer2 = create_session_signer()
        signed = signer1.sign("Hello!")
        result = signer2.verify(signed)
        assert result.valid is False

    def test_expired_message_fails(self):
        signer = SessionSigner(max_age_seconds=1)
        signed = signer.sign("Hello!")
        # Simulate expiry
        expired = SignedMessage(
            content=signed.content,
            timestamp=time.time() - 10,
            signature=signer._compute_hmac(signed.content, time.time() - 10),
            key_id=signed.key_id,
        )
        result = signer.verify(expired)
        assert result.valid is False
        assert "expired" in result.reason

    def test_future_timestamp_fails(self):
        signer = create_session_signer()
        future = SignedMessage(
            content="Hello!",
            timestamp=time.time() + 600,
            signature="fakesig",
            key_id=signer.key_id,
        )
        result = signer.verify(future)
        assert result.valid is False
        assert "future" in result.reason

    def test_key_id_mismatch_fails(self):
        signer = create_session_signer()
        signed = signer.sign("Hello!")
        wrong_key_id = SignedMessage(
            content=signed.content,
            timestamp=signed.timestamp,
            signature=signed.signature,
            key_id="wrong-key-id",
        )
        result = signer.verify(wrong_key_id)
        assert result.valid is False
        assert "Key ID mismatch" in result.reason

    def test_deterministic_key(self):
        key = b"test-key-32-bytes-long-enough!!"
        signer1 = SessionSigner(key=key)
        signer2 = SessionSigner(key=key)
        signed = signer1.sign("Hello!")
        result = signer2.verify(signed)
        assert result.valid is True

    def test_unique_keys(self):
        signer1 = create_session_signer()
        signer2 = create_session_signer()
        assert signer1.key_id != signer2.key_id
