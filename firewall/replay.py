"""Phase 16 — Attack Replay.

Every blocked/flagged/quarantined security event gets a full decision-trail record here, so an
admin can see exactly INPUT -> FIREWALL -> PII -> POISON -> POLICY -> TRUST -> FINAL DECISION for
any past event, not just the final outcome the quarantine queue or provenance log shows.
"""
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from memory.auth import require_admin

router = APIRouter(prefix="/v1/audit")

replay_events: dict = {}


def record_replay_event(
    agent_id: str,
    original_input: str,
    firewall_result: Optional[dict] = None,
    pii_result: Optional[dict] = None,
    poison_result: Optional[dict] = None,
    policy_decision: Optional[dict] = None,
    investigator_result: Optional[dict] = None,
    trust_before: Optional[float] = None,
    trust_after: Optional[float] = None,
) -> str:
    event_id = str(uuid.uuid4())
    replay_events[event_id] = {
        "event_id": event_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "agent_id": agent_id,
        "original_input": (original_input or "")[:1000],
        "firewall_result": firewall_result,
        "pii_result": pii_result,
        "poison_result": poison_result,
        "policy_decision": policy_decision,
        "investigator_result": investigator_result,
        "trust_before": trust_before,
        "trust_after": trust_after,
    }
    return event_id


@router.get("/replay")
def list_replay_events(current_agent: dict = Depends(require_admin)):
    """ADMIN only. Last 100 blocked/flagged/quarantined events."""
    events = list(replay_events.values())[-100:]
    return {"total": len(events), "events": events}


@router.get("/replay/{event_id}")
def get_replay_event(event_id: str, current_agent: dict = Depends(require_admin)):
    """ADMIN only. Full decision trail for one event: INPUT -> FIREWALL -> PII -> POISON ->
    POLICY -> [INVESTIGATOR] -> TRUST -> FINAL DECISION."""
    event = replay_events.get(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Replay event not found")
    return event
