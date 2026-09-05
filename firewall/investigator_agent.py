"""The Investigator Agent — activates only on FLAG (medium-confidence, 0.40-0.85 injection
band) decisions from the policy engine. Instead of always escalating every uncertain case to a
human, it gathers real context via two tool calls and reasons over it with an LLM:

  1. Tool call — the flagged agent's trust history (firewall/trust_engine)
  2. Tool call — semantically similar past memories the SAME agent has written before
     (pgvector search scoped to that agent's own namespace, memory/models.py)

...then asks an LLM to decide:
  - AUTO_CLEAR — consistent with the agent's normal safe behavior, let it through
  - QUARANTINE — suspicious enough to hold for admin review, not clearly malicious
  - ESCALATE   — strong rogue/compromised-agent signal, needs urgent human attention

Every tool call, the raw LLM reasoning, and the final decision are logged (in-memory
`investigator_log`, replayable via GET /investigator/logs, ADMIN-only) so an admin can see
exactly why a medium-confidence case was cleared or quarantined without reviewing it by hand.
"""
import os
import json
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends
from groq import Groq
from dotenv import load_dotenv

from firewall.trust_engine import get_or_create_agent, calculate_trust_score
from memory.auth import require_admin

load_dotenv()
router = APIRouter()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))
MODEL = os.getenv("GROQ_MODEL")

investigator_log: list[dict] = []

SYSTEM_PROMPT = """You are a security investigator for an AI memory system. You are only called \
for medium-confidence cases (0.40-0.85 injection confidence) — too uncertain to auto-block, too \
risky to silently allow. You are given the agent's trust history, semantically similar content \
the same agent has written before, and the current flagged input. Decide one of:
- AUTO_CLEAR: the input is consistent with this agent's normal, safe behavior — let it through
- QUARANTINE: suspicious enough to hold for admin review, but not clearly malicious
- ESCALATE: strong signals of a rogue/compromised agent — needs urgent human attention
Respond ONLY in this exact JSON format:
{"decision": "AUTO_CLEAR" or "QUARANTINE" or "ESCALATE", "confidence": 0.0 to 1.0, "reasoning": "brief explanation citing the trust history and/or similar memories"}"""


def _tool_get_trust_history(agent_id: str) -> dict:
    """Tool call 1: the flagged agent's trust history."""
    agent = get_or_create_agent(agent_id)
    score = calculate_trust_score(agent_id)
    return {
        "trust_score": score,
        "role": agent["role"],
        "injection_attempts": agent["injection_attempts"],
        "poisoning_attempts": agent["poisoning_attempts"],
        "role_violations": agent["role_violations"],
        "total_actions": agent["total_actions"],
    }


def _tool_search_similar_memories(agent_id: str, text: str, top_k: int = 5) -> list[dict]:
    """Tool call 2: vector-search this agent's own past memories for similar content, using the
    same pgvector store as memory/api.py. Fails soft (empty list) if the DB is unreachable — the
    investigator degrades gracefully rather than crashing the request pipeline."""
    try:
        from sentence_transformers import SentenceTransformer
        from sqlalchemy import select
        from memory.database import SessionLocal
        from memory.models import Memory
        from memory.encryption import decrypt

        embed_model = SentenceTransformer("all-MiniLM-L6-v2")
        embedding = embed_model.encode(text).tolist()
        db = SessionLocal()
        try:
            results = db.scalars(
                select(Memory)
                .where(Memory.agent_id == agent_id)
                .order_by(Memory.embedding.cosine_distance(embedding))
                .limit(top_k)
            ).all()
            return [{"id": m.id, "content_preview": decrypt(m.content)[:200]} for m in results]
        finally:
            db.close()
    except Exception:
        return []


def investigate(agent_id: str, input_text: str, injection_result: dict, policy_result: dict) -> dict:
    """Runs the full investigator flow and logs it. Returns
    {decision, confidence, reasoning, event_id, trust_history, similar_memories}."""
    trust_history = _tool_get_trust_history(agent_id)
    similar_memories = _tool_search_similar_memories(agent_id, input_text)

    user_prompt = json.dumps({
        "flagged_input": (input_text or "")[:1000],
        "firewall_classification": injection_result,
        "policy_engine_result": {k: v for k, v in (policy_result or {}).items() if k != "trust_impact"},
        "agent_trust_history": trust_history,
        "similar_past_memories": similar_memories,
    })

    decision = {
        "decision": "QUARANTINE",
        "confidence": 0.5,
        "reasoning": "LLM reasoning unavailable — defaulted to quarantine for human review",
    }
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            timeout=5.0,
        )
        content = response.choices[0].message.content.strip()
        if content.startswith("```"):
            content = content[7:] if content.startswith("```json") else content[3:]
            if content.endswith("```"):
                content = content[:-3]
        parsed = json.loads(content.strip())
        if parsed.get("decision") in ("AUTO_CLEAR", "QUARANTINE", "ESCALATE"):
            decision = parsed
    except Exception as e:
        decision["reasoning"] += f" (error: {e})"

    event_id = str(uuid.uuid4())
    investigator_log.append({
        "event_id": event_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "agent_id": agent_id,
        "input_preview": (input_text or "")[:200],
        "tool_calls": {
            "trust_history": trust_history,
            "similar_memories": similar_memories,
        },
        "decision": decision.get("decision"),
        "confidence": decision.get("confidence"),
        "reasoning": decision.get("reasoning"),
    })

    return {
        **decision,
        "event_id": event_id,
        "trust_history": trust_history,
        "similar_memories": similar_memories,
    }


@router.get("/investigator/logs")
def get_investigator_logs(current_agent: dict = Depends(require_admin)):
    return {"total": len(investigator_log), "logs": investigator_log[-100:]}
