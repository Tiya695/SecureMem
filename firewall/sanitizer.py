"""Phase 4 — minimal write-time XSS mitigation.

Memory content is free text that may later be rendered in a browser (dashboard/audit pages).
This does not attempt full HTML sanitization (no bleach dependency) — it strips the two most
common XSS injection vectors before storage: <script> blocks and inline `on*=` event-handler
attributes. Everything else is left untouched (plain text, punctuation, etc. all pass through).
"""
import re

_SCRIPT_TAG_RE = re.compile(r"<script\b[^>]*>.*?</script\s*>", re.IGNORECASE | re.DOTALL)
_SCRIPT_TAG_UNCLOSED_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
_EVENT_ATTR_RE = re.compile(r'\s+on\w+\s*=\s*(".*?"|\'.*?\'|[^\s>]+)', re.IGNORECASE)


def sanitize_text(text: str) -> str:
    """Strip <script>...</script> blocks and on*= event handler attributes from free text."""
    if not text:
        return text
    cleaned = _SCRIPT_TAG_RE.sub("", text)
    cleaned = _SCRIPT_TAG_UNCLOSED_RE.sub("", cleaned)
    cleaned = _EVENT_ATTR_RE.sub("", cleaned)
    return cleaned
