"""Phase 5 PII detector tests. Unit tests only — no live server required, except
test_memory_write_redacts_pii which needs the Postgres instance noted in docs/PROJECT_AUDIT.md.
"""
import uuid
import requests

from firewall.pii_detector import detect_pii

BASE_URL = "http://127.0.0.1:8000"


def test_detects_email():
    result = detect_pii("Contact me at jane.doe@example.com for details")
    assert result["has_pii"] is True
    assert "email" in result["pii_types"]
    assert "jane.doe@example.com" not in result["redacted_text"]
    assert "[REDACTED_EMAIL]" in result["redacted_text"]


def test_detects_indian_phone():
    result = detect_pii("Call me on 9876543210 tomorrow")
    assert result["has_pii"] is True
    assert "phone" in result["pii_types"]
    assert "9876543210" not in result["redacted_text"]


def test_detects_aadhaar():
    result = detect_pii("My Aadhaar number is 234512345678")
    assert result["has_pii"] is True
    assert "aadhaar" in result["pii_types"]


def test_detects_pan_card():
    result = detect_pii("PAN: ABCDE1234F")
    assert result["has_pii"] is True
    assert "pan_card" in result["pii_types"]


def test_detects_valid_credit_card_only():
    # 4111111111111111 is a well-known Luhn-valid test Visa number.
    result = detect_pii("Card number 4111111111111111 expires soon")
    assert result["has_pii"] is True
    assert "credit_card" in result["pii_types"]
    assert "4111111111111111" not in result["redacted_text"]

    # A Luhn-invalid 16-digit number should NOT be flagged as a credit card.
    result2 = detect_pii("Reference number 1234567890123456")
    assert "credit_card" not in result2["pii_types"]


def test_detects_password_assignment():
    result = detect_pii("Config: password=hunter2 and continue")
    assert result["has_pii"] is True
    assert "secret" in result["pii_types"]
    assert "hunter2" not in result["redacted_text"]


def test_clean_text_has_no_pii():
    result = detect_pii("The user prefers dark mode and likes tea.")
    assert result["has_pii"] is False
    assert result["pii_types"] == []
    assert result["redacted_text"] == "The user prefers dark mode and likes tea."


def test_memory_write_redacts_pii():
    """Requires a running Postgres instance behind DATABASE_URL — see docs/PROJECT_AUDIT.md."""
    agent = f"pii_agent_{uuid.uuid4().hex[:8]}"
    token = requests.post(
        f"{BASE_URL}/auth/token", json={"agent_id": agent, "role": "AGENT"}, timeout=5
    ).json()["access_token"]

    resp = requests.post(
        f"{BASE_URL}/memory/write",
        json={
            "agent_id": agent,
            "content": "Reach the user at jane.doe@example.com or 9876543210",
            "namespace": agent,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert resp.status_code == 200, resp.text

    search = requests.get(
        f"{BASE_URL}/memory/search",
        params={"agent_id": agent, "query": "reach the user", "namespace": agent, "top_k": 1},
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert search.status_code == 200, search.text
    content = search.json()["matches"][0]["content"]
    assert "jane.doe@example.com" not in content
    assert "9876543210" not in content
    assert "[REDACTED_EMAIL]" in content
