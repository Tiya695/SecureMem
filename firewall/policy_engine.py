"""Phase 8 — Security Policy Engine (+ Phase 6 quarantine store).

The single decision layer of SecureMem. Takes the firewall/PII/poison/trust signals from a
request and turns them into one final_decision: ALLOW | BLOCK | QUARANTINE | REDACT | FLAG, per
the rule table below. `/firewall/check` and `memory/write` both run every request through
`evaluate()` as their last step before honoring the result.

Rule table (highest priority first):
  1. Agent already temp-banned                          -> BLOCK
  2. 5+ attacks in 10 minutes                            -> BLOCK (+ 1hr temp ban)
  3. Injection confidence > 0.85                         -> BLOCK
  4. Combined memory risk score > 0.80                   -> QUARANTINE
  5. PII detected (and nothing worse triggered)          -> REDACT
  6. Injection confidence 0.40-0.85                      -> FLAG (Investigator Agent takes over)
  7. Otherwise                                            -> ALLOW

`trust_score < 0.30` isn't a branch of its own — trust_engine.py already auto-downgrades a agent
to READONLY at that threshold (see calculate_trust_score); evaluate() surfaces it as a
`trust_downgrade` flag on the result so callers/logs can see why.
"""
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from memory.auth import require_admin
from firewall.poison_detector import memory_risk_score

router = APIRouter()

ATTACK_WINDOW_MINUTES = 10
ATTACK_THRESHOLD = 5
BAN_DURATION_MINUTES = 60

# --- Rate-based repeated-attack tracking ---------------------------------------
_attack_timestamps: dict[str, list[datetime]] = {}
_banned_until: dict[str, datetime] = {}


def _record_attack(agent_id: str) -> None:
    _attack_timestamps.setdefault(agent_id, []).append(datetime.now())


def _recent_attack_count(agent_id: str) -> int:
    window_start = datetime.now() - timedelta(minutes=ATTACK_WINDOW_MINUTES)
    remaining = [t for t in _attack_timestamps.get(agent_id, []) if t >= window_start]
    _attack_timestamps[agent_id] = remaining
    return len(remaining)


def is_banned(agent_id: str) -> bool:
    until = _banned_until.get(agent_id)
    return until is not None and datetime.now() < until


def _apply_ban(agent_id: str) -> None:
    _banned_until[agent_id] = datetime.now() + timedelta(minutes=BAN_DURATION_MINUTES)


# --- Quarantine store -----------------------------------------------------------
quarantine_store: dict[str, dict] = {}


def add_to_quarantine(
    agent_id: str,
    content: str,
    risk_score: float,
    reason: str,
    source: str,
    investigator_verdict: Optional[dict] = None,
) -> str:
    item_id = str(uuid.uuid4())
    quarantine_store[item_id] = {
        "id": item_id,
        "agent_id": agent_id,
        "content_preview": (content or "")[:200],
        "risk_score": risk_score,
        "reason": reason,
        "source": source,  # "policy_engine" | "investigator_agent"
        "investigator_verdict": investigator_verdict,
        "status": "pending",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return item_id


# --- Policy evaluation ------------------------------------------------------------

def evaluate(
    injection_result: Optional[dict] = None,
    pii_result: Optional[dict] = None,
    poison_result: Optional[dict] = None,
    trust_score: float = 1.0,
    agent_id: str = "unknown",
    request_context: Optional[dict] = None,
) -> dict:
    """Returns {action, reason, policy_rule_triggered, trust_impact, risk_score, trust_downgrade}."""
    injection_result = injection_result or {}
    pii_result = pii_result or {}
    poison_result = poison_result or {}

    injection_confidence = injection_result.get("confidence", 0.0) if injection_result.get("is_injection") else 0.0
    poison_confidence = poison_result.get("confidence", 0.0) if poison_result.get("is_poisoned") else 0.0
    has_pii = bool(pii_result.get("has_pii"))

    risk_score = memory_risk_score(injection_confidence, poison_confidence, has_pii)
    trust_downgrade = trust_score < 0.30

    base = {"risk_score": risk_score, "trust_downgrade": trust_downgrade}

    if is_banned(agent_id):
        return {
            "action": "BLOCK",
            "reason": "Agent is temporarily banned for repeated attacks",
            "policy_rule_triggered": "temp_ban_active",
            "trust_impact": 0.0,
            **base,
        }

    if injection_result.get("is_injection") or poison_result.get("is_poisoned"):
        _record_attack(agent_id)
        if _recent_attack_count(agent_id) >= ATTACK_THRESHOLD:
            _apply_ban(agent_id)
            return {
                "action": "BLOCK",
                "reason": f"{ATTACK_THRESHOLD}+ attacks in {ATTACK_WINDOW_MINUTES} minutes — agent banned for {BAN_DURATION_MINUTES} minutes",
                "policy_rule_triggered": "rate_ban",
                "trust_impact": -0.20,
                **base,
            }

    if injection_confidence > 0.85:
        return {
            "action": "BLOCK",
            "reason": injection_result.get("reason", "High-confidence injection attack"),
            "policy_rule_triggered": "injection_high_confidence",
            "trust_impact": -0.08,
            **base,
        }

    if risk_score > 0.80:
        return {
            "action": "QUARANTINE",
            "reason": "Combined memory risk score exceeds quarantine threshold",
            "policy_rule_triggered": "risk_score_high",
            "trust_impact": -0.05,
            **base,
        }

    if has_pii and not injection_result.get("is_injection") and not poison_result.get("is_poisoned"):
        return {
            "action": "REDACT",
            "reason": "PII detected and redacted before storage",
            "policy_rule_triggered": "pii_redact",
            "trust_impact": 0.0,
            **base,
        }

    if 0.40 <= injection_confidence <= 0.85:
        return {
            "action": "FLAG",
            "reason": injection_result.get("reason", "Medium-confidence threat requires review"),
            "policy_rule_triggered": "medium_confidence_flag",
            "trust_impact": -0.02,
            **base,
        }

    return {
        "action": "ALLOW",
        "reason": "No policy violation detected",
        "policy_rule_triggered": "none",
        "trust_impact": 0.0,
        **base,
    }


# --- Quarantine review endpoints (ADMIN only) ------------------------------------

@router.get("/quarantine/list")
def list_quarantine(current_agent: dict = Depends(require_admin)):
    items = list(quarantine_store.values())
    return {"total": len(items), "items": items}


@router.post("/quarantine/approve/{item_id}")
def approve_quarantine(item_id: str, current_agent: dict = Depends(require_admin)):
    item = quarantine_store.get(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Quarantine item not found")
    item["status"] = "approved"
    return {"status": "approved", "id": item_id}


@router.delete("/quarantine/reject/{item_id}")
def reject_quarantine(item_id: str, current_agent: dict = Depends(require_admin)):
    item = quarantine_store.get(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Quarantine item not found")
    item["status"] = "rejected"
    return {"status": "rejected", "id": item_id}
