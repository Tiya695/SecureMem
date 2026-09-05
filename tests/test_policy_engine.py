"""Phase 6/8 policy engine tests. evaluate()/memory_risk_score() are unit-tested directly (no
server needed); the quarantine endpoint tests need a live server: uvicorn backend.main:app.
"""
import os
import uuid
import requests
from dotenv import load_dotenv

from firewall.poison_detector import memory_risk_score
from firewall import policy_engine
from firewall.policy_engine import evaluate

load_dotenv()
BASE_URL = "http://127.0.0.1:8000"


def _fresh_agent() -> str:
    """A unique agent id per test so the rate-ban / attack-count trackers don't leak state
    between tests (policy_engine keeps that state in module-level dicts)."""
    return f"policy_test_{uuid.uuid4().hex[:10]}"


def test_memory_risk_score_combines_signals():
    assert memory_risk_score(0.0, 0.0, False) == 0.0
    assert memory_risk_score(1.0, 0.0, False) == 0.5
    assert memory_risk_score(0.0, 1.0, False) == 0.4
    assert memory_risk_score(0.0, 0.0, True) == 0.3
    assert memory_risk_score(1.0, 1.0, True) == 1.0  # capped


def test_high_confidence_injection_blocks():
    result = evaluate(
        injection_result={"is_injection": True, "confidence": 0.95, "reason": "obvious attack"},
        trust_score=1.0,
        agent_id=_fresh_agent(),
    )
    assert result["action"] == "BLOCK"
    assert result["policy_rule_triggered"] == "injection_high_confidence"


def test_medium_confidence_flags():
    result = evaluate(
        injection_result={"is_injection": True, "confidence": 0.6, "reason": "ambiguous"},
        trust_score=1.0,
        agent_id=_fresh_agent(),
    )
    assert result["action"] == "FLAG"
    assert result["policy_rule_triggered"] == "medium_confidence_flag"


def test_clean_input_allows():
    result = evaluate(
        injection_result={"is_injection": False, "confidence": 0.02},
        trust_score=1.0,
        agent_id=_fresh_agent(),
    )
    assert result["action"] == "ALLOW"


def test_pii_alone_redacts():
    result = evaluate(
        pii_result={"has_pii": True, "pii_types": ["email"]},
        trust_score=1.0,
        agent_id=_fresh_agent(),
    )
    assert result["action"] == "REDACT"
    assert result["policy_rule_triggered"] == "pii_redact"


def test_high_risk_score_quarantines():
    # 0.5*0.5 (injection) + 0.4*1.0 (poison) + 0.3 (pii) = 0.95 -> over the 0.80 threshold, while
    # staying under the 0.85 injection-confidence BLOCK threshold so QUARANTINE is what fires.
    result = evaluate(
        injection_result={"is_injection": True, "confidence": 0.5, "reason": "borderline"},
        poison_result={"is_poisoned": True, "confidence": 1.0},
        pii_result={"has_pii": True},
        trust_score=1.0,
        agent_id=_fresh_agent(),
    )
    assert result["risk_score"] > 0.80
    assert result["action"] == "QUARANTINE"


def test_low_trust_score_flags_downgrade():
    result = evaluate(
        injection_result={"is_injection": False, "confidence": 0.0},
        trust_score=0.15,
        agent_id=_fresh_agent(),
    )
    assert result["trust_downgrade"] is True
    assert result["action"] == "ALLOW"  # downgrade is informational, doesn't block this request


def test_repeated_attacks_trigger_temp_ban():
    agent = _fresh_agent()
    attack = {"is_injection": True, "confidence": 0.9, "reason": "attack"}
    last = None
    for _ in range(5):
        last = evaluate(injection_result=attack, trust_score=1.0, agent_id=agent)
    assert last["policy_rule_triggered"] in ("rate_ban", "injection_high_confidence")
    # A 6th request must be blocked by the active ban regardless of its own content.
    result = evaluate(injection_result={"is_injection": False, "confidence": 0.0}, trust_score=1.0, agent_id=agent)
    assert result["action"] == "BLOCK"
    assert result["policy_rule_triggered"] == "temp_ban_active"


def test_quarantine_add_and_list_roundtrip():
    item_id = policy_engine.add_to_quarantine(
        agent_id="roundtrip_agent", content="suspicious text", risk_score=0.85,
        reason="test", source="policy_engine",
    )
    assert item_id in policy_engine.quarantine_store
    assert policy_engine.quarantine_store[item_id]["status"] == "pending"


def test_quarantine_endpoints_require_admin():
    agent = _fresh_agent()
    agent_token = requests.post(
        f"{BASE_URL}/auth/token", json={"agent_id": agent, "role": "AGENT"}, timeout=5
    ).json()["access_token"]

    resp = requests.get(
        f"{BASE_URL}/quarantine/list", headers={"Authorization": f"Bearer {agent_token}"}, timeout=5
    )
    assert resp.status_code == 403, resp.text

    admin_token = requests.post(
        f"{BASE_URL}/auth/token",
        json={"agent_id": "admin_qt_test", "role": "ADMIN", "admin_secret": os.getenv("ADMIN_BOOTSTRAP_SECRET")},
        timeout=5,
    ).json()["access_token"]
    resp = requests.get(
        f"{BASE_URL}/quarantine/list", headers={"Authorization": f"Bearer {admin_token}"}, timeout=5
    )
    assert resp.status_code == 200, resp.text
    assert "items" in resp.json()


def test_firewall_check_response_includes_policy_field():
    resp = requests.post(
        f"{BASE_URL}/firewall/check",
        json={"prompt": "What is the capital of France?", "agent_id": _fresh_agent()},
        timeout=10,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "policy" in body
    assert body["policy"]["action"] in ("ALLOW", "BLOCK", "QUARANTINE", "REDACT", "FLAG")
