# PII & Sensitive Memory Protection

## What counts as PII here

Email addresses, phone numbers (Indian and international), Aadhaar numbers, PAN card numbers,
credit card numbers, and password/API-key/secret-looking assignments (`password=...`,
`api_key: ...`, etc.).

## How it works

`firewall/pii_detector.py` exposes `detect_pii(text) -> {has_pii, pii_types, redacted_text}`:

- Regex-based detection per category (see the module for exact patterns).
- Credit card numbers are additionally validated with a Luhn checksum before being flagged, so an
  ordinary long number (an Aadhaar number, a phone number, an order ID) isn't mistakenly redacted
  as a card number.
- `redacted_text` replaces each match with a category placeholder (`[REDACTED_EMAIL]`,
  `[REDACTED_PHONE]`, `[REDACTED_AADHAAR]`, `[REDACTED_PAN]`, `[REDACTED_CARD]`,
  `[REDACTED_SECRET]`) — never with the raw value.

## Policy

Integrated into `memory/api.py`'s `POST /memory/write`, run **after** the Phase 4 sanitizer and
**before** anything is embedded, encrypted, or stored:

1. Content is sanitized (script tags / event handlers stripped).
2. `detect_pii()` runs on the sanitized content.
3. If PII is found, the **redacted** text — not the original — is what gets embedded, encrypted,
   and written to Postgres.
4. A provenance log entry (`write_pii_redacted`, outcome `redacted`) records that redaction
   happened for that memory id, without logging the raw PII or even the specific category list —
   an admin can look up the memory by id to see the (already-redacted) stored content, but the
   original sensitive value is never persisted anywhere, including in logs.

This means a memory containing PII is never rejected/blocked outright — it's silently cleaned and
stored safely, which matches the playbook's policy table (`PII detected in memory write → REDACT
before storage`).

## Known limitations

- Regex-based, not a full NLP/NER PII model — will miss unusual formats (e.g. non-Indian national
  ID numbers, PII embedded in unusual phrasing) and can occasionally false-positive on
  coincidentally PAN-shaped strings.
- The Indian-mobile-number pattern will also match some non-phone 10-digit numbers that happen to
  start with 6-9; this is a deliberate precision/recall tradeoff favoring not missing real phone
  numbers.
