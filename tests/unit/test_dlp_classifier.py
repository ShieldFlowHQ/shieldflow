"""Tests for the semantic DLP classifier."""

import pytest

from shieldflow.core.dlp_classifier import (
    ClassificationResult,
    SemanticDLPClassifier,
    SensitivityCategory,
    classify_content,
)


class TestSemanticDLPClassifier:
    """Test cases for the SemanticDLPClassifier."""

    def test_classify_email(self) -> None:
        """Test detection of email addresses."""
        classifier = SemanticDLPClassifier()
        result = classifier.classify("Contact john.doe@company.com for details")

        assert result.is_sensitive
        assert SensitivityCategory.PII in result.categories
        assert result.risk_score > 0

    def test_classify_ssn(self) -> None:
        """Test detection of US Social Security numbers."""
        classifier = SemanticDLPClassifier()
        result = classifier.classify("My SSN is 123-45-6789")

        assert result.is_sensitive
        assert SensitivityCategory.PII in result.categories

    def test_classify_aws_key(self) -> None:
        """Test detection of AWS access keys."""
        classifier = SemanticDLPClassifier()
        result = classifier.classify("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")

        assert result.is_sensitive
        assert SensitivityCategory.SECRETS in result.categories

    def test_classify_credit_card(self) -> None:
        """Test detection of credit card numbers."""
        classifier = SemanticDLPClassifier()
        # Visa card number
        result = classifier.classify("Card: 4111111111111111")

        assert result.is_sensitive
        assert SensitivityCategory.FINANCIAL in result.categories

    def test_classify_public_content(self) -> None:
        """Test that public content is not flagged."""
        classifier = SemanticDLPClassifier()
        result = classifier.classify("The weather is sunny today")

        assert not result.is_sensitive
        assert result.risk_score == 0.0
        assert len(result.findings) == 0

    def test_classify_phone_number(self) -> None:
        """Test detection of phone numbers."""
        classifier = SemanticDLPClassifier()
        result = classifier.classify("Call me at (555) 123-4567")

        assert result.is_sensitive
        assert SensitivityCategory.PII in result.categories

    def test_classify_contextual(self) -> None:
        """Test contextual analysis layer."""
        classifier = SemanticDLPClassifier(enable_contextual=True)
        # This uses contextual clues "my" + "is" + SSN pattern
        result = classifier.classify("Can you help me? My ssn is 123-45-6789")

        # Should detect via either regex or contextual
        assert result.is_sensitive

    def test_classify_bearer_token(self) -> None:
        """Test detection of bearer tokens."""
        classifier = SemanticDLPClassifier()
        result = classifier.classify(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        )

        assert result.is_sensitive
        assert SensitivityCategory.SECRETS in result.categories

    def test_classify_medical_record(self) -> None:
        """Test detection of medical record identifiers."""
        classifier = SemanticDLPClassifier()
        result = classifier.classify("Patient MRN: ABC123456")

        assert result.is_sensitive
        assert SensitivityCategory.HEALTH in result.categories

    def test_classify_multiple_findings(self) -> None:
        """Test detection of multiple sensitive items."""
        classifier = SemanticDLPClassifier()
        result = classifier.classify(
            "Contact john@company.com (SSN: 123-45-6789) about the card 4111111111111111"
        )

        assert result.is_sensitive
        assert len(result.findings) >= 3
        assert SensitivityCategory.PII in result.categories
        assert SensitivityCategory.FINANCIAL in result.categories

    def test_convenience_function(self) -> None:
        """Test the classify_content convenience function."""
        result = classify_content("Email me at test@example.com")

        assert result.is_sensitive

    def test_masked_values(self) -> None:
        """Test that sensitive values are masked in findings."""
        classifier = SemanticDLPClassifier()
        result = classifier.classify("Contact test@company.com")

        assert result.findings
        # Value should be masked (not reveal full email)
        finding = result.findings[0]
        assert "*" in finding.value

    def test_empty_content(self) -> None:
        """Test handling of empty content."""
        classifier = SemanticDLPClassifier()
        result = classifier.classify("")

        assert not result.is_sensitive
        assert result.risk_score == 0.0

    def test_confidence_scoring(self) -> None:
        """Test confidence scoring."""
        classifier = SemanticDLPClassifier()

        # High-confidence pattern (SSN)
        result = classifier.classify("SSN: 123-45-6789")
        assert result.confidence > 0.8

        # Lower-confidence pattern
        result = classifier.classify("Name: John Doe")
        # This might not trigger regex, contextual might have lower confidence


class TestSensitivityCategories:
    """Test sensitivity category handling."""

    def test_pii_category(self) -> None:
        """Test PII category detection."""
        classifier = SemanticDLPClassifier()

        # Various PII types
        pii_content = "Email: user@test.com, Phone: 555-123-4567"
        result = classifier.classify(pii_content)

        assert SensitivityCategory.PII in result.categories

    def test_secrets_category(self) -> None:
        """Test secrets category detection."""
        classifier = SemanticDLPClassifier()

        secrets_content = "API_KEY=super_secret_key_12345678901234567890"
        result = classifier.classify(secrets_content)

        assert SensitivityCategory.SECRETS in result.categories

    def test_financial_category(self) -> None:
        """Test financial category detection."""
        classifier = SemanticDLPClassifier()

        financial_content = "Credit card: 5500000000000004"
        result = classifier.classify(financial_content)

        assert SensitivityCategory.FINANCIAL in result.categories
