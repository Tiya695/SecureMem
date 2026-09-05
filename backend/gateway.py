"""Phase 10 — SecureMem Gateway.

The single entry point for an external AI application: instead of calling firewall, memory, and
trust separately, POST /v1/gateway/chat runs the complete pipeline (auth -> firewall -> PII ->
poison -> policy engine [-> Investigator Agent on FLAG] -> LLM) in one call. Every /v1/* endpoint
here delegates to the already-tested logic in firewall/*.py and memory/api.py rather than
duplicating it — this file is a thin routing/composition layer.
"""
import os
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from memory.auth import get_current_agent, require_admin
from backend.llm_providers import call_llm

router = APIRouter(prefix="/v1")

# In-process calls to our own already-running endpoints — same pattern memory/api.py already
# uses for provenance logging (see log_provenance), kept consistent rather than refactoring the
# whole codebase's internals into shared functions in this batch.
INTERNAL_BASE = "http://127.0.0.1:8000"


class GatewayChatRequest(BaseModel):
    message: str = Field(..., max_length=10_000)
    agent_id: str = Field(..., max_length=200)
    conversation_history: Optional[list] = None


class SecurityCheckRequest(BaseModel):
    prompt: str = Field(..., max_length=10_000)
    agent_id: str = Field(..., max_length=200)


class GatewayWriteRequest(BaseModel):
    agent_id: str = Field(..., max_length=200)
    content: str = Field(..., max_length=10_000)
    namespace: str = Field(..., max_length=200)
    metadata: Optional[dict] = {}


def _forward_auth_header(request: Request) -> dict:
    auth = request.headers.get("authorization")
    return {"Authorization": auth} if auth else {}


def _run_security_pipeline(prompt: str, agent_id: str) -> dict:
    """Runs /firewall/check (which already chains PII/poison/policy-engine/Investigator Agent —
    see firewall/policy_engine.py and firewall/investigator_agent.py) and returns its response."""
    resp = httpx.post(
        f"{INTERNAL_BASE}/firewall/check",
        json={"prompt": prompt, "agent_id": agent_id},
        timeout=15.0,
    )
    resp.raise_for_status()
    return resp.json()


def _is_blocked(check_result: dict) -> bool:
    policy = check_result.get("policy", {})
    action = policy.get("action", "ALLOW")
    if action in ("BLOCK", "QUARANTINE"):
        return True
    investigator = check_result.get("investigator")
    if action == "FLAG" and investigator and investigator.get("decision") in ("QUARANTINE", "ESCALATE"):
        return True
    return False


@router.post("/gateway/chat")
def gateway_chat(body: GatewayChatRequest):
    """(1) firewall/PII/poison/policy pipeline via /firewall/check, (2) block early without
    calling the LLM if unsafe, (3) forward to the configured LLM provider if allowed, (4) return
    the response plus the full security metadata. Provenance + trust updates already happen
    inside /firewall/check — not duplicated here."""
    check_result = _run_security_pipeline(body.message, body.agent_id)

    if _is_blocked(check_result):
        investigator = check_result.get("investigator") or {}
        return {
            "blocked": True,
            "reason": investigator.get("reasoning") or check_result.get("reason"),
            "confidence": check_result.get("confidence"),
            "policy": check_result.get("policy"),
            "investigator": investigator or None,
        }

    llm_result = call_llm(body.message, body.conversation_history or [])
    return {
        "blocked": False,
        "response": llm_result.get("text"),
        "llm": {k: v for k, v in llm_result.items() if k != "text"},
        "security": {
            "is_injection": check_result.get("is_injection"),
            "confidence": check_result.get("confidence"),
            "policy": check_result.get("policy"),
        },
    }


@router.post("/security/check")
def security_check(body: SecurityCheckRequest):
    """Check a prompt without forwarding to an LLM — for testing/preview."""
    return _run_security_pipeline(body.prompt, body.agent_id)


@router.post("/memory/write")
def gateway_memory_write(request: Request, body: GatewayWriteRequest):
    resp = httpx.post(
        f"{INTERNAL_BASE}/memory/write",
        json=body.model_dump(),
        headers=_forward_auth_header(request),
        timeout=15.0,
    )
    return _passthrough(resp)


@router.get("/memory/search")
def gateway_memory_search(request: Request, agent_id: str, query: str, namespace: str, top_k: int = 5):
    resp = httpx.get(
        f"{INTERNAL_BASE}/memory/search",
        params={"agent_id": agent_id, "query": query, "namespace": namespace, "top_k": top_k},
        headers=_forward_auth_header(request),
        timeout=15.0,
    )
    return _passthrough(resp)


@router.delete("/memory/{memory_id}")
def gateway_memory_delete(request: Request, memory_id: str):
    resp = httpx.request(
        "DELETE",
        f"{INTERNAL_BASE}/memory/delete",
        json={"memory_id": memory_id},
        headers=_forward_auth_header(request),
        timeout=15.0,
    )
    return _passthrough(resp)


@router.get("/trust/{agent_id}")
def gateway_trust_score(agent_id: str):
    resp = httpx.get(f"{INTERNAL_BASE}/trust/score/{agent_id}", timeout=10.0)
    return _passthrough(resp)


@router.get("/audit/logs")
def gateway_audit_logs(
    current_agent: dict = Depends(require_admin),
    agent_id: Optional[str] = None,
    outcome: Optional[str] = None,
    decision: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    """ADMIN-only full audit log with filters — unlike the legacy, open /provenance/logs (kept
    open for the existing dashboard pages, see firewall/provenance.py), this is the properly
    gated endpoint the playbook calls for."""
    from firewall.provenance import get_logs
    return get_logs(agent_id=agent_id, outcome=outcome, decision=decision, date_from=date_from, date_to=date_to)


@router.get("/quarantine")
def gateway_quarantine(current_agent: dict = Depends(require_admin)):
    """ADMIN: quarantine queue (same data as GET /quarantine/list, exposed under the gateway's
    /v1 namespace too, per the playbook's endpoint list)."""
    from firewall.policy_engine import quarantine_store
    items = list(quarantine_store.values())
    return {"total": len(items), "items": items}


def _passthrough(resp: httpx.Response):
    """Mirrors the internal endpoint's status code and body exactly, so gateway consumers see
    the same errors (401/403/404/422) the underlying endpoint would have given them directly."""
    try:
        body = resp.json()
    except ValueError:
        body = {"detail": resp.text}
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=body.get("detail", body))
    return body
