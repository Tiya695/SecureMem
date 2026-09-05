"""Phase 4 input-security tests. Requires a live server: uvicorn backend.main:app --port 8000
for the HTTP-level tests; test_sanitizer_* run standalone with no server needed.
"""
import os
import uuid
import requests
from dotenv import load_dotenv

from firewall.sanitizer import sanitize_text

load_dotenv()

BASE_URL = "http://127.0.0.1:8000"


def test_sanitizer_strips_script_tag():
    dirty = 'Hello <script>alert(1)</script> world'
    clean = sanitize_text(dirty)
    assert "<script" not in clean.lower()
    assert "alert(1)" not in clean
    assert "Hello" in clean and "world" in clean


def test_sanitizer_strips_event_handler_attribute():
    dirty = '<img src=x onerror="alert(1)">'
    clean = sanitize_text(dirty)
    assert "onerror" not in clean.lower()


def test_sanitizer_leaves_plain_text_untouched():
    plain = "The user's favorite hobby is painting landscapes."
    assert sanitize_text(plain) == plain


def test_firewall_check_rejects_oversized_prompt():
    resp = requests.post(
        f"{BASE_URL}/firewall/check",
        json={"prompt": "x" * 10_001, "agent_id": "size_test"},
        timeout=5,
    )
    assert resp.status_code == 422, resp.text


def test_memory_write_rejects_oversized_content():
    agent = f"size_agent_{uuid.uuid4().hex[:8]}"
    token = requests.post(
        f"{BASE_URL}/auth/token", json={"agent_id": agent, "role": "AGENT"}, timeout=5
    ).json()["access_token"]

    resp = requests.post(
        f"{BASE_URL}/memory/write",
        json={"agent_id": agent, "content": "x" * 10_001, "namespace": agent},
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert resp.status_code == 422, resp.text


def test_memory_write_sanitizes_script_tag():
    """Requires a running Postgres instance behind DATABASE_URL — see docs/PROJECT_AUDIT.md."""
    agent = f"xss_agent_{uuid.uuid4().hex[:8]}"
    token = requests.post(
        f"{BASE_URL}/auth/token", json={"agent_id": agent, "role": "AGENT"}, timeout=5
    ).json()["access_token"]

    resp = requests.post(
        f"{BASE_URL}/memory/write",
        json={
            "agent_id": agent,
            "content": 'Notes about the project <script>alert(1)</script> deadline',
            "namespace": agent,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert resp.status_code == 200, resp.text

    search = requests.get(
        f"{BASE_URL}/memory/search",
        params={"agent_id": agent, "query": "project deadline", "namespace": agent, "top_k": 1},
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert search.status_code == 200, search.text
    matches = search.json()["matches"]
    assert len(matches) == 1
    assert "<script" not in matches[0]["content"].lower()
