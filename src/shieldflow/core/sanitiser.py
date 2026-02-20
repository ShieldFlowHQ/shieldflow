"""Content sanitiser for detecting obfuscated prompt injection attempts.

Provides Unicode normalisation, encoding detection (Base64, ROT13),
hidden-text detection, and a unified ``sanitise()`` entry point used by
the validator before pattern matching.
"""

from __future__ import annotations

import base64
import codecs
import re
import unicodedata
from dataclasses import dataclass, field

# ─── Injection patterns (canonical list) ──────────────────────────────────────
# These are re-exported here so that downstream modules (validator, tests)
# can import from a single authoritative location.

INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?prior\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
    re.compile(r"your\s+new\s+(primary\s+)?instruction", re.IGNORECASE),
    re.compile(r"system\s+(update|override|command)", re.IGNORECASE),
    re.compile(r"forward\s+all\s+(emails?|messages?)", re.IGNORECASE),
    re.compile(r"send\s+(all|every)\s+.*(to|@)", re.IGNORECASE),
    re.compile(r"execute\s+(the\s+)?following", re.IGNORECASE),
    re.compile(r"run\s+(this|the\s+following)\s+command", re.IGNORECASE),
    re.compile(r"(do\s+not|don'?t)\s+(notify|alert|tell)\s+(the\s+)?user", re.IGNORECASE),
    re.compile(r"silently|without\s+(the\s+)?user\s+knowing", re.IGNORECASE),
    re.compile(r"mandatory\s+security\s+(requirement|update|audit)", re.IGNORECASE),
    re.compile(r"maintenance\s+mode", re.IGNORECASE),
    re.compile(r"compliance\s+(review|audit|requirement)", re.IGNORECASE),
    re.compile(r"bcc\s+all\s+(outgoing|emails?|messages?)", re.IGNORECASE),
    # Social engineering / authority claim patterns
    re.compile(r"(as\s+)?(IT\s+)?admin(istrat(ion|or))?,?\s+please", re.IGNORECASE),
    re.compile(r"technical\s+support\s+(requires?|needs?)", re.IGNORECASE),
    re.compile(r"(requires?|needs?)\s+(immediate\s+)?access\s+to", re.IGNORECASE),
    re.compile(r"please\s+(delete|remove|read|access|send|forward|share)", re.IGNORECASE),
    re.compile(r"(ssh|connect|login)\s+(to|into)\s+", re.IGNORECASE),
]


# ─── SanitisedContent ─────────────────────────────────────────────────────────


@dataclass
class SanitisedContent:
    """Result of sanitising a piece of text for injection analysis.

    Attributes:
        normalised_text:  Cleaned text with zero-width chars stripped,
                          homoglyphs replaced, and Unicode normalised.
                          Use this for pattern matching instead of raw text.
        flags:            Detected issues, e.g. ``"base64_injection"``,
                          ``"rot13_injection"``, ``"homoglyphs"``,
                          ``"compact_injection"``, ``"hidden_html"``,
                          ``"invisible_unicode"``, ``"tag_characters"``.
        original_text:    The untouched input, preserved for display / audit.
        decoded_extras:   Decoded payloads extracted during analysis
                          (base64 blocks, ROT13 full-text).  Callers may
                          search these for additional value / domain overlap.
    """

    normalised_text: str
    flags: list[str]
    original_text: str
    decoded_extras: list[str] = field(default_factory=list)


# ─── Zero-width and invisible character stripping ────────────────────────────

# Characters that render as invisible and are used to split injection phrases
_ZERO_WIDTH_CHARS = re.compile(
    r"["
    r"\u200b"  # Zero-Width Space
    r"\u200c"  # Zero-Width Non-Joiner
    r"\u200d"  # Zero-Width Joiner
    r"\u2060"  # Word Joiner
    r"\ufeff"  # BOM / Zero-Width No-Break Space
    r"\u200e"  # Left-to-Right Mark
    r"\u200f"  # Right-to-Left Mark
    r"\u202a-\u202e"  # Directional formatting chars
    r"\u2066-\u2069"  # Isolate / pop directional formatting
    r"\ufff9-\ufffb"  # Interlinear annotation anchors/separators
    r"]",
    re.UNICODE,
)

# Unicode tag block U+E0000–U+E007F (invisible tag characters)
_TAG_CHARS = re.compile(r"[\U000e0000-\U000e007f]", re.UNICODE)


def strip_zero_width(text: str) -> str:
    """Strip zero-width and invisible Unicode characters from *text*.

    This is the same transformation formerly performed by
    ``validator._strip_zero_width``.  Moved here so the sanitiser is the
    single source of truth for text normalisation.
    """
    text = _ZERO_WIDTH_CHARS.sub("", text)
    text = _TAG_CHARS.sub("", text)
    return text


# ─── Homoglyph normalisation ─────────────────────────────────────────────────

# Cyrillic and Greek characters that are visually identical (or near-identical)
# to Latin ASCII characters, commonly used to evade pattern matching.
_HOMOGLYPHS: dict[str, str] = {
    # ── Cyrillic → Latin (lowercase) ──────────────────────────────────────────
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u043e": "o",  # о → o
    "\u0440": "r",  # р → r
    "\u0441": "c",  # с → c
    "\u0445": "x",  # х → x
    "\u0456": "i",  # і → i  (Ukrainian)
    "\u0438": "u",  # и → u  (approximate)
    "\u04cf": "l",  # ӏ → l
    "\u0443": "y",  # у → y
    "\u0432": "b",  # в → b  (approximate)
    # ── Cyrillic → Latin (uppercase) ──────────────────────────────────────────
    "\u0406": "I",  # І → I  (Ukrainian)
    "\u0408": "J",  # Ј → J
    "\u0410": "A",  # А → A
    "\u0412": "B",  # В → B
    "\u0415": "E",  # Е → E
    "\u041a": "K",  # К → K
    "\u041c": "M",  # М → M
    "\u041d": "H",  # Н → H
    "\u041e": "O",  # О → O
    "\u0420": "P",  # Р → P
    "\u0421": "C",  # С → C
    "\u0422": "T",  # Т → T
    "\u0425": "X",  # Х → X
    # ── Greek → Latin (lowercase) ─────────────────────────────────────────────
    "\u03b9": "i",  # ι → i
    "\u03bf": "o",  # ο → o
    "\u03b1": "a",  # α → a
    "\u03b5": "e",  # ε → e (Greek epsilon)
    "\u03c1": "p",  # ρ → p
    "\u03c5": "u",  # υ → u
    # ── Greek → Latin (uppercase) ─────────────────────────────────────────────
    "\u0391": "A",  # Α → A
    "\u0392": "B",  # Β → B
    "\u0395": "E",  # Ε → E
    "\u0396": "Z",  # Ζ → Z
    "\u0397": "H",  # Η → H
    "\u0399": "I",  # Ι → I  (Greek capital iota)
    "\u039a": "K",  # Κ → K
    "\u039c": "M",  # Μ → M
    "\u039d": "N",  # Ν → N
    "\u039f": "O",  # Ο → O
    "\u03a1": "P",  # Ρ → P
    "\u03a4": "T",  # Τ → T
    "\u03a5": "Y",  # Υ → Y
    "\u03a7": "X",  # Χ → X
}


def normalize_unicode(text: str) -> str:
    """Apply comprehensive Unicode normalisation for injection detection.

    Steps applied in order:

    1. Strip zero-width / invisible chars (``strip_zero_width``).
    2. NFKC normalisation — converts fullwidth Latin, mathematical
       alphanumeric symbols, and other compatibility characters to their
       ASCII/basic-plane equivalents.
    3. Homoglyph mapping — replace Cyrillic and Greek lookalikes with
       their ASCII equivalents.
    4. Strip combining diacritics (Unicode category ``Mn``) used to
       visually alter characters while preserving base code-points.

    Args:
        text: Raw input text.

    Returns:
        Normalised text suitable for pattern matching.
    """
    # 1. Strip zero-width / invisible chars
    text = strip_zero_width(text)

    # 2. NFKC: fullwidth A-Z/a-z → ASCII, mathematical bold/italic → ASCII, etc.
    text = unicodedata.normalize("NFKC", text)

    # 3. Homoglyph substitution
    text = "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)

    # 4. Strip combining diacritics (NFD decompose → filter Mn → no recompose)
    nfd = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in nfd if unicodedata.category(ch) != "Mn")

    return text


# ─── Compact (zero-width-joined) injection phrase detection ──────────────────

# When zero-width characters are used to split injection phrases (e.g.
# "ign\u200bore\u200call\u200bprevious\u200binstruction"), stripping them
# concatenates the words without spaces.  We check the concatenated form
# against these compact phrases.
_COMPACT_INJECTION_PHRASES: tuple[str, ...] = (
    "ignoreallpreviousinstruction",
    "ignoreallpriorinstruction",
    "ignorepriorinstruction",
    "ignorepreviousinstruction",
    "youarenow",
    "yournewinstruction",
    "yournewprimaryinstruction",
    "systemoverride",
    "systemupdate",
    "systemcommand",
    "executethefollowing",
    "runthiscommand",
    "runthefollowingcommand",
    "forwardallmail",
    "forwardallmessage",
    "sendallemail",
    "sendallmessage",
    "donotnotifytheuser",
    "donotnotify",
    "withouttheuserknowing",
    "mandatorysecurityrequirement",
    "maintenancemode",
    "compliancereview",
    "bccalloutgoing",
)


def _detect_compact_injection(text: str) -> bool:
    """Return ``True`` if *text* contains a compact injection phrase.

    After stripping zero-width chars *and* all whitespace, we check
    whether any known injection keyword sequence appears as a substring of
    the resulting compacted string.
    """
    compact = re.sub(r"\s+", "", _ZERO_WIDTH_CHARS.sub("", text)).lower()
    return any(phrase in compact for phrase in _COMPACT_INJECTION_PHRASES)


# ─── Base64 detection ─────────────────────────────────────────────────────────

# Minimum length for a base64 block to be considered suspicious
_MIN_BASE64_LEN = 20
_BASE64_BLOCK = re.compile(rf"[A-Za-z0-9+/]{{{_MIN_BASE64_LEN},}}={{0,2}}")


def _try_decode_base64(candidate: str) -> str | None:
    """Attempt to decode *candidate* as base64, returning decoded text or ``None``."""
    # Ensure correct padding
    remainder = len(candidate) % 4
    if remainder:
        candidate += "=" * (4 - remainder)
    try:
        decoded_bytes = base64.b64decode(candidate)
        # Only return if decodable as UTF-8 (or close to it)
        return decoded_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return None


def extract_base64_decoded(text: str) -> list[str]:
    """Extract and decode all base64-like blocks found in *text*.

    Only blocks of at least ``_MIN_BASE64_LEN`` characters are considered.
    Blocks that cannot be decoded as UTF-8 are silently skipped.

    Args:
        text: Source text to scan.

    Returns:
        List of successfully decoded string payloads.
    """
    decoded: list[str] = []
    for match in _BASE64_BLOCK.finditer(text):
        result = _try_decode_base64(match.group())
        if result:
            decoded.append(result)
    return decoded


def detect_base64_injection(
    text: str,
    injection_patterns: list[re.Pattern[str]] | None = None,
) -> tuple[bool, list[str], list[str]]:
    """Scan *text* for base64-encoded injection payloads.

    Args:
        text: Source text to scan.
        injection_patterns: Patterns to match against decoded blocks.
                            Defaults to :data:`INJECTION_PATTERNS`.

    Returns:
        ``(flagged, flags, decoded_blocks)`` where *flagged* is ``True`` if
        any decoded block matched an injection pattern.
    """
    patterns = injection_patterns if injection_patterns is not None else INJECTION_PATTERNS
    decoded_blocks = extract_base64_decoded(text)
    for decoded in decoded_blocks:
        if any(p.search(decoded) for p in patterns):
            return True, ["base64_injection"], decoded_blocks
    return False, [], decoded_blocks


# ─── ROT13 detection ──────────────────────────────────────────────────────────


def detect_rot13_injection(
    text: str,
    injection_patterns: list[re.Pattern[str]] | None = None,
) -> tuple[bool, list[str], list[str]]:
    """Check whether ROT13-decoding *text* reveals injection patterns.

    The decoded text is only flagged if the *original* text does **not**
    already match any injection pattern (to avoid redundant flags).

    Args:
        text: Source text to decode and check.
        injection_patterns: Patterns to match against.  Defaults to
                            :data:`INJECTION_PATTERNS`.

    Returns:
        ``(flagged, flags, [decoded_text])``
    """
    patterns = injection_patterns if injection_patterns is not None else INJECTION_PATTERNS
    decoded = codecs.encode(text, "rot_13")
    if any(p.search(decoded) for p in patterns):
        original_matches = any(p.search(text) for p in patterns)
        if not original_matches:
            return True, ["rot13_injection"], [decoded]
    return False, [], [decoded]


# ─── Hidden text detection ────────────────────────────────────────────────────

_HIDDEN_HTML_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'<[^>]+\bstyle\s*=\s*["\'][^"\']*display\s*:\s*none', re.IGNORECASE),
    re.compile(r'<[^>]+\bstyle\s*=\s*["\'][^"\']*visibility\s*:\s*hidden', re.IGNORECASE),
    re.compile(r"<[^>]+\bhidden\b", re.IGNORECASE),
    re.compile(r'<[^>]+\bstyle\s*=\s*["\'][^"\']*font-size\s*:\s*0', re.IGNORECASE),
    re.compile(
        r'<[^>]+\bstyle\s*=\s*["\'][^"\']*color\s*:\s*(white|#fff(?:fff)?)\b',
        re.IGNORECASE,
    ),
    re.compile(r'<[^>]+\bstyle\s*=\s*["\'][^"\']*opacity\s*:\s*0', re.IGNORECASE),
]


def detect_hidden_text(text: str) -> tuple[bool, list[str]]:
    """Detect hidden text patterns in *text*.

    Checks for:

    * HTML elements with ``display:none``, ``visibility:hidden``,
      zero font-size, white-on-white colour, or ``opacity:0``.
    * Invisible Unicode format characters (category ``Cf``) above U+007F.
    * Unicode tag block characters (U+E0000–U+E007F).
    * Interlinear annotation characters.

    Args:
        text: Input text (may contain HTML markup).

    Returns:
        ``(detected, flags)``
    """
    flags: list[str] = []

    # HTML hidden elements
    if any(p.search(text) for p in _HIDDEN_HTML_PATTERNS):
        flags.append("hidden_html")

    # Invisible Unicode format characters (non-ASCII only to keep it fast)
    has_invisible_cf = any(unicodedata.category(ch) == "Cf" and ord(ch) > 0x7F for ch in text)
    if has_invisible_cf:
        flags.append("invisible_unicode")

    # Unicode tag block (U+E0000–U+E007F)
    if any(0xE0000 <= ord(ch) <= 0xE007F for ch in text):
        flags.append("tag_characters")

    return bool(flags), flags


# ─── Main sanitise() entry point ─────────────────────────────────────────────


def sanitise(
    text: str,
    injection_patterns: list[re.Pattern[str]] | None = None,
) -> SanitisedContent:
    """Sanitise *text* and return a :class:`SanitisedContent` result.

    This is the primary entry point for all content normalisation and
    obfuscation detection.  The validator calls this on every untrusted
    block before pattern matching.

    Processing pipeline:

    1. Detect homoglyphs (Cyrillic / Greek lookalikes) before normalisation.
    2. Detect compact (ZWS-joined) injection phrases.
    3. Normalise Unicode (strip ZWS, NFKC, homoglyph map, strip diacritics).
    4. Detect base64-encoded injection payloads.
    5. Detect ROT13-encoded injection payloads.
    6. Detect hidden text (HTML + invisible Unicode).

    Args:
        text: The raw text to sanitise (untouched original preserved).
        injection_patterns: Optional override for injection patterns used in
                            base64 / ROT13 detection.  Defaults to the
                            module-level :data:`INJECTION_PATTERNS`.

    Returns:
        :class:`SanitisedContent` with normalised text, flags, original,
        and any decoded payloads.
    """
    patterns = injection_patterns if injection_patterns is not None else INJECTION_PATTERNS
    flags: list[str] = []
    decoded_extras: list[str] = []

    # 1. Detect homoglyphs (before normalisation destroys the evidence)
    if any(ch in _HOMOGLYPHS for ch in text):
        flags.append("homoglyphs")

    # 2. Detect compact injection (ZWS-split phrases)
    if _detect_compact_injection(text):
        flags.append("compact_injection")

    # 3. Unicode normalisation
    normalised = normalize_unicode(text)

    # 4. Base64 injection detection
    b64_flagged, b64_flags, b64_decoded = detect_base64_injection(text, patterns)
    flags.extend(b64_flags)
    decoded_extras.extend(b64_decoded)

    # 5. ROT13 injection detection
    rot_flagged, rot_flags, rot_decoded = detect_rot13_injection(text, patterns)
    flags.extend(rot_flags)
    # Only include ROT13 decoded if it actually triggered (avoid noise)
    if rot_flagged:
        decoded_extras.extend(rot_decoded)

    # 6. Hidden text detection
    _, hidden_flags = detect_hidden_text(text)
    flags.extend(hidden_flags)

    return SanitisedContent(
        normalised_text=normalised,
        flags=flags,
        original_text=text,
        decoded_extras=decoded_extras,
    )
