"""Semantic DLP classifier for content classification beyond regex.

This module provides content classification that goes beyond simple pattern
matching by using:
1. Contextual analysis (surrounding text matters)
2. Structural understanding (document structure, data formats)
3. Semantic intent detection (what is the user trying to do?)
4. Similarity-based detection (comparing against known sensitive patterns)

This is a PoC implementation - production use would leverage ML models.

Design
-----
The classifier uses a layered approach:
- Layer 1: Fast regex patterns for known high-confidence patterns
- Layer 2: Contextual analysis for ambiguous cases
- Layer 3: Semantic similarity for novel variants

Classification categories:
- PII: Personally Identifiable Information (names, SSNs, addresses, etc.)
- SECRETS: API keys, passwords, tokens, certificates
- FINANCIAL: Credit cards, bank accounts, financial data
- HEALTH: Medical records, health identifiers (HIPAA-relevant)
- CUSTOM: Organization-specific sensitive data

Usage::

    classifier = SemanticDLPClassifier()

    # Classify content
    result = classifier.classify(
        content="Please send the report to john.doe@company.com",
        context={"user_intent": "business_communication"}
    )

    # result.categories contains detected sensitivity types
    # result.risk_score is 0.0-1.0
    # result.confidence is confidence in the classification
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SensitivityCategory(Enum):
    """Categories of sensitive content."""

    PII = "pii"
    SECRETS = "secrets"
    FINANCIAL = "financial"
    HEALTH = "health"
    CUSTOM = "custom"
    PUBLIC = "public"


@dataclass
class ClassificationResult:
    """Result of content classification.

    Attributes:
        categories: Set of detected sensitivity categories.
        risk_score: Overall risk score (0.0 = safe, 1.0 = highly sensitive).
        confidence: Confidence in the classification (0.0-1.0).
        findings: Detailed findings with location and evidence.
        is_sensitive: True if any sensitive content was detected.
    """

    categories: set[SensitivityCategory] = field(default_factory=set)
    risk_score: float = 0.0
    confidence: float = 0.0
    findings: list[ClassificationFinding] = field(default_factory=list)
    _is_sensitive: bool = field(default=False, repr=False)

    @property
    def is_sensitive(self) -> bool:
        """True if any sensitive content was detected."""
        return bool(self.categories and SensitivityCategory.PUBLIC not in self.categories)


@dataclass
class ClassificationFinding:
    """A single classification finding with evidence.

    Attributes:
        category: The sensitivity category detected.
        label: Specific label (e.g., "email", "ssn", "api_key").
        value: The sensitive value (should be masked in logs).
        location: Where in the content it was found (start-end indices).
        confidence: Confidence in this specific detection.
        method: How it was detected ("regex", "contextual", "semantic").
    """

    category: SensitivityCategory
    label: str
    value: str
    start: int
    end: int
    confidence: float
    method: str = "regex"


# Context keywords that indicate sensitive content
CONTEXT_INDICATORS: dict[SensitivityCategory, list[str]] = {
    SensitivityCategory.PII: [
        "personal", "private", "confidential", "employee", "customer",
        "home address", "phone number", "date of birth", "ssn", "social security",
    ],
    SensitivityCategory.SECRETS: [
        "password", "secret", "api key", "token", "credential", "private key",
        "access token", "auth", "bearer", "encryption key", "aws secret",
    ],
    SensitivityCategory.FINANCIAL: [
        "bank account", "routing number", "credit card", "card number",
        "payment", "invoice", "salary", "compensation", "financial",
    ],
    SensitivityCategory.HEALTH: [
        "medical", "health", "patient", "diagnosis", "prescription",
        "insurance", "hipaa", "clinical", "treatment", "diagnosis",
    ],
}


class SemanticDLPClassifier:
    """Semantic DLP classifier for content classification.

    This classifier uses multiple detection methods:
    - Regex patterns for known formats (fast path)
    - Contextual analysis for ambiguous content
    - Similarity detection for novel variants

    Args:
        enable_contextual: Enable contextual analysis (slower but more accurate).
        enable_semantic: Enable semantic similarity detection (requires embeddings).
        custom_patterns: Additional regex patterns to check.
    """

    def __init__(
        self,
        enable_contextual: bool = True,
        enable_semantic: bool = False,
        custom_patterns: dict[SensitivityCategory, list[tuple[str, re.Pattern[str]]]] | None = None,
    ) -> None:
        self._enable_contextual = enable_contextual
        self._enable_semantic = enable_semantic
        self._custom_patterns = custom_patterns or {}

        # Compile regex patterns for each category
        self._patterns = self._build_patterns()

    def _build_patterns(
        self,
    ) -> dict[SensitivityCategory, list[tuple[str, re.Pattern[str]]]]:
        """Build regex patterns for each sensitivity category."""
        patterns: dict[SensitivityCategory, list[tuple[str, re.Pattern[str]]]] = {
            SensitivityCategory.PII: [
                # Email addresses
                ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", re.IGNORECASE)),
                # US SSN
                ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
                # US phone numbers (various formats)
                ("phone", re.compile(r"\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b")),
                # Names (common patterns - names are hard to regex reliably)
                ("name_heuristic", re.compile(r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b")),
            ],
            SensitivityCategory.SECRETS: [
                # AWS keys
                ("aws_access_key", re.compile(r"\b(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b")),
                ("aws_secret_key", re.compile(r"\b[A-Za-z0-9/+=]{40}\b(?=(?:.*[A-Z])?(?:.*[a-z])?(?:.*\d)?(?:.*[/+])?$)")),
                # Generic API keys (heuristic)
                ("api_key", re.compile(r"\b(?:api[_-]?key|apikey|api_secret|secret_key)[=:]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?", re.IGNORECASE)),
                # Bearer tokens (JWT format - more flexible)
                ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+\b", re.IGNORECASE)),
                # Private keys
                ("private_key", re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----")),
                # Generic secrets
                ("secret_heuristic", re.compile(r"\b(?:password|passwd|pwd|credential|token|auth)[=:]\s*['\"]?[^\s'\"]{8,}['\"]?", re.IGNORECASE)),
            ],
            SensitivityCategory.FINANCIAL: [
                # Credit card numbers (Visa, MC, Amex, Discover)
                ("credit_card", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")),
                # Bank account (basic)
                ("bank_account", re.compile(r"\b(?:account|acct)[_\s]?(?:no|number|#)?[:.\s]*[0-9]{8,17}\b", re.IGNORECASE)),
                # IBAN
                ("iban", re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b")),
            ],
            SensitivityCategory.HEALTH: [
                # Medical record number
                ("mrn", re.compile(r"\b(?:MRN|medical[_\s]?record[_\s]?#?)\s*:?\s*[A-Z0-9]{6,10}\b", re.IGNORECASE)),
                # Health insurance
                ("insurance_id", re.compile(r"\b(?:insurance|policy)[_\s]?(?:id|number|#)?\s*:?\s*[A-Z0-9]{8,15}\b", re.IGNORECASE)),
                # ICD codes (simplified)
                ("icd_code", re.compile(r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b")),
            ],
            SensitivityCategory.CUSTOM: [],
            SensitivityCategory.PUBLIC: [],
        }

        # Add custom patterns
        for category, custom in self._custom_patterns.items():
            if category in patterns:
                patterns[category].extend(custom)
            else:
                patterns[category] = custom

        return patterns

    def classify(
        self,
        content: str,
        context: dict[str, Any] | None = None,
    ) -> ClassificationResult:
        """Classify content for sensitive information.

        Args:
            content: The text content to classify.
            context: Optional context (e.g., {"user_intent": "..."}).

        Returns:
            ClassificationResult with detected categories and risk score.
        """
        context = context or {}
        result = ClassificationResult()

        # Layer 1: Fast regex pattern matching
        self._classify_regex(content, result)

        # Layer 2: Contextual analysis
        if self._enable_contextual:
            self._classify_contextual(content, context, result)

        # Layer 3: Semantic similarity (placeholder for ML-based)
        if self._enable_semantic:
            self._classify_semantic(content, result)

        # Calculate final risk score
        self._calculate_risk_score(result)

        return result

    def _classify_regex(
        self,
        content: str,
        result: ClassificationResult,
    ) -> None:
        """Layer 1: Regex-based pattern matching."""
        for category, patterns in self._patterns.items():
            if category == SensitivityCategory.PUBLIC:
                continue

            for label, pattern in patterns:
                for match in pattern.finditer(content):
                    # Calculate confidence based on pattern specificity
                    confidence = self._calculate_pattern_confidence(label, match.group())

                    finding = ClassificationFinding(
                        category=category,
                        label=label,
                        value=self._mask_value(match.group()),
                        start=match.start(),
                        end=match.end(),
                        confidence=confidence,
                        method="regex",
                    )

                    # Avoid duplicate findings
                    if not self._is_duplicate_finding(result.findings, finding):
                        result.findings.append(finding)
                        result.categories.add(category)

    def _classify_contextual(
        self,
        content: str,
        context: dict[str, Any],
        result: ClassificationResult,
    ) -> None:
        """Layer 2: Contextual analysis for ambiguous content.

        This layer analyzes surrounding text and context to detect
        sensitive content that regex might miss or misclassify.
        """
        content_lower = content.lower()

        for category, indicators in CONTEXT_INDICATORS.items():
            # Check if context indicators are present
            indicator_count = sum(1 for ind in indicators if ind in content_lower)

            if indicator_count >= 2:  # Require multiple indicators
                # Look for unlabeled sensitive-like patterns near indicators
                # This catches things like "my SSN is XXX-XX-XXXX" where
                # the label appears but regex might not catch the value

                # Check for masked/near-masked patterns
                masked_patterns = [
                    (r"\b\w+\s+is\s+\d{3}-\d{2}-\d{4}\b", "ssn"),
                    (r"\b\w+\s+is\s+[\w.+-]+@[\w-]+\.[\w.-]+\b", "email"),
                    (r"\b\w+\s+(?:phone|mobile|cell)\s+(?:\#|is)?\s*\+?[\d\s-]{10,}\b", "phone"),
                ]

                for pattern_str, label in masked_patterns:
                    pattern = re.compile(pattern_str, re.IGNORECASE)
                    for match in pattern.finditer(content):
                        # If this wasn't caught by regex (would be in findings already)
                        if not any(f.start == match.start() for f in result.findings):
                            finding = ClassificationFinding(
                                category=category,
                                label=f"{label}_contextual",
                                value=self._mask_value(match.group()),
                                start=match.start(),
                                end=match.end(),
                                confidence=0.7,
                                method="contextual",
                            )
                            result.findings.append(finding)
                            result.categories.add(category)

    def _classify_semantic(
        self,
        content: str,
        result: ClassificationResult,
    ) -> None:
        """Layer 3: Semantic similarity-based detection.

        This is a placeholder for ML-based detection.
        In production, this would use embeddings to compare against
        known sensitive content patterns.
        """
        # Placeholder: In production, use embeddings
        # For now, this demonstrates the interface
        pass

    def _calculate_pattern_confidence(self, label: str, value: str) -> float:
        """Calculate confidence based on pattern specificity."""
        # High-confidence patterns (specific formats)
        high_confidence = {"email", "ssn", "aws_access_key", "credit_card", "iban"}
        medium_confidence = {"phone", "api_key", "private_key", "bank_account"}

        if label in high_confidence:
            return 0.95
        elif label in medium_confidence:
            return 0.8
        else:
            return 0.6

    def _is_duplicate_finding(
        self,
        findings: list[ClassificationFinding],
        new_finding: ClassificationFinding,
    ) -> bool:
        """Check if a finding is a duplicate."""
        return any(
            f.start == new_finding.start and f.end == new_finding.end
            for f in findings
        )

    def _mask_value(self, value: str) -> str:
        """Mask sensitive values for logging."""
        if len(value) <= 4:
            return "*" * len(value)
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    def _calculate_risk_score(self, result: ClassificationResult) -> None:
        """Calculate overall risk score based on findings."""
        if not result.findings:
            result.risk_score = 0.0
            result.confidence = 1.0
            return

        # Weight by category severity
        category_weights = {
            SensitivityCategory.SECRETS: 1.0,
            SensitivityCategory.FINANCIAL: 0.9,
            SensitivityCategory.HEALTH: 0.9,
            SensitivityCategory.PII: 0.7,
            SensitivityCategory.CUSTOM: 0.5,
        }

        weighted_sum = 0.0
        total_confidence = 0.0

        for finding in result.findings:
            weight = category_weights.get(finding.category, 0.5)
            weighted_sum += weight * finding.confidence
            total_confidence += finding.confidence

        result.risk_score = min(weighted_sum / len(result.findings), 1.0) if result.findings else 0.0
        result.confidence = total_confidence / len(result.findings) if result.findings else 0.0


def classify_content(
    content: str,
    context: dict[str, Any] | None = None,
) -> ClassificationResult:
    """Convenience function for quick content classification.

    Usage::

        result = classify_content("Please email john@company.com the report")
        if result.is_sensitive:
            print(f"Risk score: {result.risk_score}")
    """
    classifier = SemanticDLPClassifier()
    return classifier.classify(content, context)
