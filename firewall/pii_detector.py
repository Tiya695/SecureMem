"""Phase 5 — PII & sensitive-memory protection.

detect_pii(text) scans free text for common categories of personally identifiable / sensitive
information and returns a redacted version safe to store. This is regex-based (no external PII
library dependency) — it favours catching the common, high-signal cases described in the
playbook over exhaustive coverage of every possible PII format worldwide.

Detected categories: email, phone (Indian + international), Aadhaar number, PAN card, credit
card number (Luhn-checked to cut down on false positives from random 16-digit numbers), and
password/secret-looking key=value assignments.
"""
import re
from dataclasses import dataclass, field

# --- Patterns -----------------------------------------------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Indian mobile numbers: optional +91/91/0 prefix, then a 10-digit number starting 6-9.
PHONE_INDIA_RE = re.compile(r"(?<!\d)(?:\+91[\-\s]?|91[\-\s]?|0)?[6-9]\d{9}(?!\d)")

# General international format: +<country code> then 7-14 digits, optionally grouped with
# spaces/dashes/parens. Deliberately requires a leading '+' to avoid matching arbitrary numbers.
PHONE_INTL_RE = re.compile(r"\+\d{1,3}[\-\s]?\(?\d{1,4}\)?(?:[\-\s]?\d{2,4}){2,4}")

# Aadhaar: 12 digits, first digit 2-9, commonly grouped as 4-4-4.
AADHAAR_RE = re.compile(r"(?<!\d)[2-9]\d{3}[\-\s]?\d{4}[\-\s]?\d{4}(?!\d)")

# PAN card: 5 letters, 4 digits, 1 letter (India).
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")

# Candidate credit-card-shaped numbers (13-19 digits, optionally grouped in 4s with spaces/dashes).
CREDIT_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")

# password / secret / api-key style key=value or "key: value" assignments.
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*\S+"
)


def _luhn_valid(digits: str) -> bool:
    """Standard Luhn checksum, used to cut down false positives on random long digit runs."""
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass
class PIIResult:
    has_pii: bool
    pii_types: list = field(default_factory=list)
    redacted_text: str = ""

    def as_dict(self) -> dict:
        return {
            "has_pii": self.has_pii,
            "pii_types": self.pii_types,
            "redacted_text": self.redacted_text,
        }


def detect_pii(text: str) -> dict:
    """Detect PII in `text` and return {has_pii, pii_types, redacted_text}."""
    if not text:
        return PIIResult(has_pii=False, pii_types=[], redacted_text=text or "").as_dict()

    redacted = text
    found: list[str] = []

    if SECRET_ASSIGNMENT_RE.search(redacted):
        found.append("secret")
        redacted = SECRET_ASSIGNMENT_RE.sub("[REDACTED_SECRET]", redacted)

    if EMAIL_RE.search(redacted):
        found.append("email")
        redacted = EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)

    if AADHAAR_RE.search(redacted):
        found.append("aadhaar")
        redacted = AADHAAR_RE.sub("[REDACTED_AADHAAR]", redacted)

    if PAN_RE.search(redacted):
        found.append("pan_card")
        redacted = PAN_RE.sub("[REDACTED_PAN]", redacted)

    # Credit card: validate each digit-run candidate with Luhn before treating it as a match,
    # so ordinary long numbers (e.g. an Aadhaar number, a phone number) aren't double-flagged.
    def _cc_sub(m: re.Match) -> str:
        digits = re.sub(r"[ \-]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            if "credit_card" not in found:
                found.append("credit_card")
            return "[REDACTED_CARD]"
        return m.group(0)

    redacted = CREDIT_CARD_CANDIDATE_RE.sub(_cc_sub, redacted)

    if PHONE_INDIA_RE.search(redacted):
        found.append("phone")
        redacted = PHONE_INDIA_RE.sub("[REDACTED_PHONE]", redacted)
    elif PHONE_INTL_RE.search(redacted):
        found.append("phone")
        redacted = PHONE_INTL_RE.sub("[REDACTED_PHONE]", redacted)

    return PIIResult(has_pii=bool(found), pii_types=found, redacted_text=redacted).as_dict()
