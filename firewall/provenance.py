from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

router = APIRouter()

# In-memory provenance log (acts like a database table for now) — stays the primary read path.
# Phase 9 adds a best-effort DB write-through (see record_log) so history survives a restart.
provenance_logs = []


class ProvenanceLog(BaseModel):
    operation: str      # write, search, delete
    memory_id: str
    agent_id: str
    timestamp: str
    outcome: str        # success, blocked, flagged


class LogRequest(BaseModel):
    operation: str
    memory_id: str
    agent_id: str
    outcome: str
    # Phase 9 extended fields — all optional so every existing caller of POST /provenance/log
    # (which only ever sent the 4 fields above) keeps working unchanged.
    ip_address: Optional[str] = None
    request_id: Optional[str] = None
    classification: Optional[str] = None
    risk_score: Optional[float] = None
    trust_before: Optional[float] = None
    trust_after: Optional[float] = None
    final_decision: Optional[str] = None
    policy_rule_triggered: Optional[str] = None


def _persist_log(log_entry: dict) -> None:
    """Best-effort DB write-through — never allowed to fail the request."""
    try:
        from memory.database import SessionLocal
        from memory.models import ProvenanceLogDB

        db = SessionLocal()
        try:
            db.add(ProvenanceLogDB(
                operation=log_entry["operation"],
                memory_id=log_entry.get("memory_id"),
                agent_id=log_entry["agent_id"],
                outcome=log_entry["outcome"],
                ip_address=log_entry.get("ip_address"),
                request_id=log_entry.get("request_id"),
                classification=log_entry.get("classification"),
                risk_score=log_entry.get("risk_score"),
                trust_before=log_entry.get("trust_before"),
                trust_after=log_entry.get("trust_after"),
                final_decision=log_entry.get("final_decision"),
                policy_rule_triggered=log_entry.get("policy_rule_triggered"),
            ))
            db.commit()
        finally:
            db.close()
    except Exception:
        pass


def record_log(
    operation: str,
    memory_id: str,
    agent_id: str,
    outcome: str,
    ip_address: Optional[str] = None,
    request_id: Optional[str] = None,
    classification: Optional[str] = None,
    risk_score: Optional[float] = None,
    trust_before: Optional[float] = None,
    trust_after: Optional[float] = None,
    final_decision: Optional[str] = None,
    policy_rule_triggered: Optional[str] = None,
) -> dict:
    """Shared entry point for every provenance write — used by both the POST /provenance/log
    endpoint and callers that already run in-process (e.g. backend/main.py's /firewall/check)
    and don't need a self-referential HTTP round-trip. None of these fields carry free-form user
    content (they're IDs/enums/scores), so there is no raw-PII redaction concern here — the
    fields that *could* carry PII (memory content) are never logged, only the memory's id."""
    log_entry = {
        "operation": operation,
        "memory_id": memory_id,
        "agent_id": agent_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "outcome": outcome,
        "ip_address": ip_address,
        "request_id": request_id,
        "classification": classification,
        "risk_score": risk_score,
        "trust_before": trust_before,
        "trust_after": trust_after,
        "final_decision": final_decision,
        "policy_rule_triggered": policy_rule_triggered,
    }
    provenance_logs.append(log_entry)
    _persist_log(log_entry)
    return log_entry


@router.post("/provenance/log")
def add_log(request: LogRequest):
    log_entry = record_log(
        operation=request.operation,
        memory_id=request.memory_id,
        agent_id=request.agent_id,
        outcome=request.outcome,
        ip_address=request.ip_address,
        request_id=request.request_id,
        classification=request.classification,
        risk_score=request.risk_score,
        trust_before=request.trust_before,
        trust_after=request.trust_after,
        final_decision=request.final_decision,
        policy_rule_triggered=request.policy_rule_triggered,
    )
    return {"message": "Log recorded", "log": log_entry}


@router.get("/provenance/logs")
def get_logs(
    agent_id: Optional[str] = None,
    outcome: Optional[str] = None,
    decision: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    """Kept open/unauthenticated — dashboard.html, audit.html, and admin.html all already call
    this without sending an Authorization header, and none of the logged fields carry raw
    sensitive content (see record_log's docstring), so gating it now would break those existing
    pages without a matching frontend change (out of scope — see docs/AUTH_AUDIT.md). The new
    filters below are opt-in query params; calling this exactly as before still returns exactly
    what it always did. A fully ADMIN-gated equivalent is `GET /v1/audit/logs` (Phase 10 gateway).
    """
    logs = provenance_logs
    if agent_id:
        logs = [l for l in logs if l.get("agent_id") == agent_id]
    if outcome:
        logs = [l for l in logs if l.get("outcome") == outcome]
    if decision:
        logs = [l for l in logs if l.get("final_decision") == decision]
    if date_from:
        logs = [l for l in logs if l.get("timestamp", "") >= date_from]
    if date_to:
        logs = [l for l in logs if l.get("timestamp", "") <= date_to]

    return {
        "total": len(logs),
        "logs": logs[-100:]
    }


@router.get("/provenance/logs/{agent_id}")
def get_logs_by_agent(agent_id: str):
    # Return logs for a specific agent
    agent_logs = [log for log in provenance_logs if log["agent_id"] == agent_id]
    return {
        "agent_id": agent_id,
        "total": len(agent_logs),
        "logs": agent_logs
    }
