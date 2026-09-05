# The Investigator Agent

## Why

Without it, every medium-confidence case (injection classifier confidence 0.40–0.85 — too
uncertain to auto-block, too risky to silently allow) would just sit in a queue for a human
admin to look at one by one. The Investigator Agent activates automatically on exactly that band
and does the first pass of the review itself, using real context instead of the confidence score
alone — so most medium-confidence cases get resolved (cleared or clearly quarantined/escalated)
without waiting on a human, and the ones that do need a human get a full rationale attached
already.

## When it runs

Only when `firewall/policy_engine.py`'s `evaluate()` returns `action: "FLAG"` — i.e. only the
0.40–0.85 injection-confidence band. High-confidence attacks (>0.85) are still blocked
immediately; low-confidence/clean input is still allowed immediately. The investigator is
deliberately not on the hot path for the common cases.

## What it does (`firewall/investigator_agent.py`)

1. **Tool call — trust history.** Pulls the flagged agent's current trust score, role, and raw
   counters (injection attempts, poisoning attempts, role violations, total actions) from
   `firewall/trust_engine.py`.
2. **Tool call — similar past memories.** Vector-searches (pgvector, the same store
   `memory/api.py` uses) that *same agent's own* past memories for content semantically similar
   to the current flagged input, scoped by `agent_id` — this is real production data, not a
   separate demo store. Degrades gracefully (empty list) if the database is unreachable rather
   than failing the whole request.
3. **LLM reasoning.** Sends both tool results plus the current input and its firewall
   classification to an LLM (same Groq model as the firewall classifier) with a system prompt
   that asks it to decide:
   - `AUTO_CLEAR` — consistent with this agent's normal, safe behavior
   - `QUARANTINE` — suspicious enough to hold for admin review, not clearly malicious
   - `ESCALATE` — strong rogue/compromised-agent signal, needs urgent human attention

   The model must respond with strict JSON: `{"decision": ..., "confidence": ..., "reasoning": ...}`.
   If the LLM call fails for any reason, the investigator **fails safe** — it defaults to
   `QUARANTINE` with a reasoning string noting the failure, rather than silently allowing the
   request through.
4. **Logging.** Every tool call's output, the raw decision, and the reasoning are appended to
   `investigator_log` (in-memory, replayable via `GET /investigator/logs`, ADMIN-only) — an admin
   can see exactly why any medium-confidence case was cleared or quarantined, including the full
   trust-history and similar-memories context the LLM was given.

## What happens to the decision

- `AUTO_CLEAR` — the request proceeds; the response still includes the full `investigator` object
  so the decision is visible, but nothing is quarantined.
- `QUARANTINE` / `ESCALATE` — added to the same `quarantine_store` the policy engine's own
  risk-based quarantine uses, tagged `source: "investigator_agent"` with the full verdict
  attached, so `GET /quarantine/list` shows the LLM's reasoning alongside the item.

## Response shape (`/firewall/check`, when `policy.action == "FLAG"`)

```json
{
  "agent_id": "...",
  "is_injection": true,
  "confidence": 0.62,
  "attack_type": "...",
  "reason": "...",
  "policy": { "action": "FLAG", "...": "..." },
  "investigator": {
    "decision": "AUTO_CLEAR | QUARANTINE | ESCALATE",
    "confidence": 0.0,
    "reasoning": "...",
    "event_id": "...",
    "trust_history": { "...": "..." },
    "similar_memories": [ { "id": "...", "content_preview": "..." } ]
  }
}
```

These fields are purely additive to `/firewall/check`'s existing response — nothing that already
reads `is_injection`/`confidence`/`attack_type`/`reason` (e.g. `simulation.html`) is affected.
