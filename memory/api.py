from fastapi import APIRouter, HTTPException, Depends, Request, Query
from pydantic import BaseModel, Field
from sentence_transformers import SentenceTransformer
from sqlalchemy import select, delete
from typing import Optional
from datetime import datetime
import hashlib
import os
import uuid
import httpx

from memory.database import SessionLocal
from memory.models import Memory, MemoryVersion
from memory.encryption import encrypt, decrypt
from memory.auth import create_access_token, get_current_agent, check_namespace_access, check_write_permission, require_admin
from firewall.rate_limit import limiter
from firewall.sanitizer import sanitize_text
from firewall.pii_detector import detect_pii


def _content_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()

router = APIRouter()

model = SentenceTransformer('all-MiniLM-L6-v2')


def log_provenance(operation: str, memory_id: str, agent_id: str, outcome: str, **extra):
    """Best-effort call to the provenance logger. Never breaks the main request if it fails.
    `extra` accepts the Phase 9 fields (risk_score, trust_before, trust_after, final_decision,
    policy_rule_triggered, classification) — all optional, omit any that don't apply."""
    try:
        httpx.post("http://127.0.0.1:8000/provenance/log", json={
            "operation": operation,
            "memory_id": memory_id,
            "agent_id": agent_id,
            "outcome": outcome,
            **extra,
        }, timeout=2.0)
    except Exception:
        pass


class WriteRequest(BaseModel):
    agent_id: str = Field(..., max_length=200)
    content: str = Field(..., max_length=10_000)
    namespace: str = Field(..., max_length=200)
    metadata: Optional[dict] = {}


class DeleteRequest(BaseModel):
    memory_id: str = Field(..., max_length=200)


class UpdateRequest(BaseModel):
    content: str = Field(..., max_length=10_000)
    change_reason: Optional[str] = Field(None, max_length=500)


class TokenRequest(BaseModel):
    agent_id: str = Field(..., max_length=200)
    role: str  # ADMIN, AGENT, READONLY
    admin_secret: Optional[str] = Field(None, max_length=200)  # required only when role == ADMIN, see Phase 2/3 hardening


@router.post("/auth/token")
@limiter.limit("60/minute")
def get_token(request: Request, req: TokenRequest):
    if req.role not in ("ADMIN", "AGENT", "READONLY"):
        raise HTTPException(status_code=400, detail="Role must be ADMIN, AGENT, or READONLY")

    # Phase 2/3 hardening: previously ANY caller could self-issue a valid ADMIN token just by
    # declaring role="ADMIN" — no credential check existed at all. There is no real user/account
    # database in this project (AGENT/READONLY remain self-service by design for the demo), so the
    # minimal fix that doesn't require building a full accounts system is to gate ADMIN issuance
    # behind a shared secret the operator sets in .env. If ADMIN_BOOTSTRAP_SECRET is unset, ADMIN
    # tokens cannot be minted at all (fail closed).
    if req.role == "ADMIN":
        expected = os.getenv("ADMIN_BOOTSTRAP_SECRET")
        if not expected or req.admin_secret != expected:
            raise HTTPException(status_code=403, detail="Invalid or missing admin_secret for ADMIN role")

    token = create_access_token(req.agent_id, req.role)
    return {"access_token": token, "token_type": "bearer", "agent_id": req.agent_id, "role": req.role}


@router.post("/memory/write")
@limiter.limit("20/minute")
def write_memory(request: Request, req: WriteRequest, current_agent: dict = Depends(get_current_agent)):
    check_write_permission(current_agent)
    check_namespace_access(current_agent, req.namespace)

    # Phase 4: strip <script> blocks / on*= handlers before this content is embedded or stored.
    clean_content = sanitize_text(req.content)

    # Phase 5: detect and redact PII before anything is embedded or stored. The redacted text
    # (never the raw PII) is what gets embedded/encrypted/logged.
    pii_result = detect_pii(clean_content)
    stored_content = pii_result["redacted_text"] if pii_result["has_pii"] else clean_content

    # Phase 6/8: run the sanitized+redacted content through the poison detector and policy
    # engine before anything is persisted.
    from firewall.poison_detector import assess_poison
    from firewall.trust_engine import calculate_trust_score
    from firewall.policy_engine import evaluate as evaluate_policy, add_to_quarantine

    poison_result = assess_poison(stored_content)
    trust_score = calculate_trust_score(req.agent_id)
    policy_result = evaluate_policy(
        pii_result=pii_result,
        poison_result=poison_result,
        trust_score=trust_score,
        agent_id=req.agent_id,
    )

    # This write path doesn't mutate the agent's trust counters itself, so before/after are the
    # same value here — still logged for a consistent provenance schema across all operations.
    policy_log_fields = dict(
        risk_score=policy_result["risk_score"],
        trust_before=trust_score,
        trust_after=trust_score,
        final_decision=policy_result["action"],
        policy_rule_triggered=policy_result["policy_rule_triggered"],
    )

    if policy_result["action"] in ("BLOCK", "QUARANTINE"):
        from firewall.replay import record_replay_event
        record_replay_event(
            agent_id=req.agent_id,
            original_input=req.content,
            pii_result=pii_result,
            poison_result=poison_result,
            policy_decision=policy_result,
            trust_before=trust_score,
            trust_after=trust_score,
        )

    if policy_result["action"] == "BLOCK":
        log_provenance("write_blocked", "n/a", req.agent_id, "blocked", **policy_log_fields)
        return {"status": "blocked", "reason": policy_result["reason"], "policy": policy_result}

    if policy_result["action"] == "QUARANTINE":
        quarantine_id = add_to_quarantine(
            agent_id=req.agent_id,
            content=stored_content,
            risk_score=policy_result["risk_score"],
            reason=policy_result["reason"],
            source="policy_engine",
        )
        log_provenance("write_quarantined", quarantine_id, req.agent_id, "quarantined", **policy_log_fields)
        return {"status": "quarantined", "quarantine_id": quarantine_id, "policy": policy_result}

    embedding = model.encode(stored_content).tolist()
    db = SessionLocal()
    try:
        mem = Memory(
            id=str(uuid.uuid4()),
            agent_id=req.agent_id,
            content=encrypt(stored_content),
            embedding=embedding,
            namespace=req.namespace,
            extra_metadata=req.metadata
        )
        db.add(mem)
        # Phase 7: record the initial version so /memory/{id}/history has a version 1 to show
        # and later rollbacks always have somewhere safe to land.
        db.add(MemoryVersion(
            memory_id=mem.id,
            version_number=1,
            agent_id=req.agent_id,
            operation="create",
            previous_content_hash=None,
            current_content_hash=_content_hash(stored_content),
            change_reason="initial write",
            content_snapshot=mem.content,
        ))
        db.commit()
        if pii_result["has_pii"]:
            # Log that PII was found + redacted, but never the raw PII itself or the pii_types
            # list beyond what's needed to audit the policy — memory_id lets an admin trace it.
            log_provenance("write_pii_redacted", mem.id, req.agent_id, "redacted", **policy_log_fields)
        log_provenance("write", mem.id, req.agent_id, "success", **policy_log_fields)
        return {"status": "stored", "id": mem.id, "policy": policy_result}
    finally:
        db.close()


@router.get("/memory/search")
def search_memory(
    agent_id: str = Query(..., max_length=200),
    query: str = Query(..., max_length=2_000),
    namespace: str = Query(..., max_length=200),
    top_k: int = Query(5, ge=1, le=50),
    current_agent: dict = Depends(get_current_agent),
):
    check_namespace_access(current_agent, namespace)

    embedding = model.encode(query).tolist()
    db = SessionLocal()
    try:
        results = db.scalars(
            select(Memory)
            .where(Memory.namespace == namespace)
            .order_by(Memory.embedding.cosine_distance(embedding))
            .limit(top_k)
        ).all()
        return {
            "matches": [
                {"id": m.id, "content": decrypt(m.content), "agent_id": m.agent_id}
                for m in results
            ]
        }
    finally:
        db.close()


@router.delete("/memory/delete")
def delete_memory(req: DeleteRequest, current_agent: dict = Depends(get_current_agent)):
    check_write_permission(current_agent)

    db = SessionLocal()
    try:
        mem = db.scalar(select(Memory).where(Memory.id == req.memory_id))
        if mem is None:
            raise HTTPException(status_code=404, detail="Memory not found")

        check_namespace_access(current_agent, mem.namespace)

        db.execute(delete(Memory).where(Memory.id == req.memory_id))
        db.commit()
        log_provenance("delete", req.memory_id, current_agent["agent_id"], "success")
        return {"status": "deleted", "id": req.memory_id}
    finally:
        db.close()


@router.post("/memory/{memory_id}/update")
@limiter.limit("20/minute")
def update_memory(request: Request, memory_id: str, req: UpdateRequest, current_agent: dict = Depends(get_current_agent)):
    """Phase 7: update an existing memory's content, versioning the previous content first."""
    check_write_permission(current_agent)

    db = SessionLocal()
    try:
        mem = db.scalar(select(Memory).where(Memory.id == memory_id))
        if mem is None:
            raise HTTPException(status_code=404, detail="Memory not found")
        check_namespace_access(current_agent, mem.namespace)

        # Same write-time pipeline as /memory/write: sanitize, redact PII, then policy-check.
        clean_content = sanitize_text(req.content)
        pii_result = detect_pii(clean_content)
        new_content = pii_result["redacted_text"] if pii_result["has_pii"] else clean_content

        from firewall.poison_detector import assess_poison
        from firewall.trust_engine import calculate_trust_score
        from firewall.policy_engine import evaluate as evaluate_policy, add_to_quarantine

        poison_result = assess_poison(new_content)
        trust_score = calculate_trust_score(current_agent["agent_id"])
        policy_result = evaluate_policy(
            pii_result=pii_result, poison_result=poison_result, trust_score=trust_score,
            agent_id=current_agent["agent_id"],
        )
        if policy_result["action"] == "BLOCK":
            log_provenance("update_blocked", memory_id, current_agent["agent_id"], "blocked")
            return {"status": "blocked", "reason": policy_result["reason"], "policy": policy_result}
        if policy_result["action"] == "QUARANTINE":
            quarantine_id = add_to_quarantine(
                agent_id=current_agent["agent_id"], content=new_content,
                risk_score=policy_result["risk_score"], reason=policy_result["reason"],
                source="policy_engine",
            )
            log_provenance("update_quarantined", quarantine_id, current_agent["agent_id"], "quarantined")
            return {"status": "quarantined", "quarantine_id": quarantine_id, "policy": policy_result}

        previous_hash = _content_hash(decrypt(mem.content))
        new_version_number = mem.version + 1

        db.add(MemoryVersion(
            memory_id=mem.id,
            version_number=new_version_number,
            agent_id=current_agent["agent_id"],
            operation="update",
            previous_content_hash=previous_hash,
            current_content_hash=_content_hash(new_content),
            change_reason=req.change_reason,
            content_snapshot=encrypt(new_content),
        ))

        mem.content = encrypt(new_content)
        mem.embedding = model.encode(new_content).tolist()
        mem.version = new_version_number
        db.commit()

        log_provenance("update", mem.id, current_agent["agent_id"], "success")
        return {"status": "updated", "id": mem.id, "version": new_version_number, "policy": policy_result}
    finally:
        db.close()


@router.get("/memory/{memory_id}/history")
def get_memory_history(memory_id: str, current_agent: dict = Depends(require_admin)):
    """ADMIN only. Full version history for one memory, oldest first."""
    db = SessionLocal()
    try:
        versions = db.scalars(
            select(MemoryVersion)
            .where(MemoryVersion.memory_id == memory_id)
            .order_by(MemoryVersion.version_number)
        ).all()
        if not versions:
            raise HTTPException(status_code=404, detail="No version history for this memory id")
        return {
            "memory_id": memory_id,
            "versions": [
                {
                    "version_number": v.version_number,
                    "timestamp": v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else None,
                    "agent_id": v.agent_id,
                    "operation": v.operation,
                    "previous_content_hash": v.previous_content_hash,
                    "current_content_hash": v.current_content_hash,
                    "change_reason": v.change_reason,
                }
                for v in versions
            ],
        }
    finally:
        db.close()


@router.post("/memory/{memory_id}/rollback/{version_number}")
def rollback_memory(memory_id: str, version_number: int, current_agent: dict = Depends(require_admin)):
    """ADMIN only. Restores the memory's content to a prior version — e.g. if a later update
    turned out to be poisoned. Recorded as a new version (operation="rollback"), not a delete of
    the versions that came after, so the full history stays intact."""
    db = SessionLocal()
    try:
        mem = db.scalar(select(Memory).where(Memory.id == memory_id))
        if mem is None:
            raise HTTPException(status_code=404, detail="Memory not found")

        target_version = db.scalar(
            select(MemoryVersion)
            .where(MemoryVersion.memory_id == memory_id, MemoryVersion.version_number == version_number)
        )
        if target_version is None:
            raise HTTPException(status_code=404, detail=f"Version {version_number} not found for this memory")

        restored_content = decrypt(target_version.content_snapshot)
        previous_hash = _content_hash(decrypt(mem.content))
        new_version_number = mem.version + 1

        db.add(MemoryVersion(
            memory_id=mem.id,
            version_number=new_version_number,
            agent_id=current_agent["agent_id"],
            operation="rollback",
            previous_content_hash=previous_hash,
            current_content_hash=_content_hash(restored_content),
            change_reason=f"rollback to version {version_number}",
            content_snapshot=target_version.content_snapshot,
        ))

        mem.content = target_version.content_snapshot
        mem.embedding = model.encode(restored_content).tolist()
        mem.version = new_version_number
        db.commit()

        log_provenance("rollback", mem.id, current_agent["agent_id"], "success")
        return {"status": "rolled_back", "id": mem.id, "restored_from_version": version_number, "new_version": new_version_number}
    finally:
        db.close()