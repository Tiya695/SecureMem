from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from sentence_transformers import SentenceTransformer
from sqlalchemy import select, delete
from typing import Optional
from datetime import datetime
import os
import uuid
import httpx

from memory.database import SessionLocal
from memory.models import Memory
from memory.encryption import encrypt, decrypt
from memory.auth import create_access_token, get_current_agent, check_namespace_access, check_write_permission
from firewall.rate_limit import limiter

router = APIRouter()

model = SentenceTransformer('all-MiniLM-L6-v2')


def log_provenance(operation: str, memory_id: str, agent_id: str, outcome: str):
    """Best-effort call to the provenance logger. Never breaks the main request if it fails."""
    try:
        httpx.post("http://127.0.0.1:8000/provenance/log", json={
            "operation": operation,
            "memory_id": memory_id,
            "agent_id": agent_id,
            "outcome": outcome
        }, timeout=2.0)
    except Exception:
        pass


class WriteRequest(BaseModel):
    agent_id: str
    content: str
    namespace: str
    metadata: Optional[dict] = {}


class DeleteRequest(BaseModel):
    memory_id: str


class TokenRequest(BaseModel):
    agent_id: str
    role: str  # ADMIN, AGENT, READONLY
    admin_secret: Optional[str] = None  # required only when role == ADMIN, see Phase 2/3 hardening


@router.post("/auth/token")
@limiter.limit("20/minute")
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

    embedding = model.encode(req.content).tolist()
    db = SessionLocal()
    try:
        mem = Memory(
            id=str(uuid.uuid4()),
            agent_id=req.agent_id,
            content=encrypt(req.content),
            embedding=embedding,
            namespace=req.namespace,
            extra_metadata=req.metadata
        )
        db.add(mem)
        db.commit()
        log_provenance("write", mem.id, req.agent_id, "success")
        return {"status": "stored", "id": mem.id}
    finally:
        db.close()


@router.get("/memory/search")
def search_memory(agent_id: str, query: str, namespace: str, top_k: int = 5, current_agent: dict = Depends(get_current_agent)):
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