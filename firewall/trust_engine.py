from fastapi import APIRouter
from datetime import datetime

router = APIRouter()

# In-memory store for agent behaviour history
agent_history = {}

def get_or_create_agent(agent_id: str):
    if agent_id not in agent_history:
        agent_history[agent_id] = {
            "injection_attempts": 0,
            "poisoning_attempts": 0,
            "total_reads": 0,
            "total_writes": 0,
            "last_violation_time": None,
            "role_violations": 0,
            "total_actions": 0,
            "role": "AGENT"
        }
    return agent_history[agent_id]

def calculate_trust_score(agent_id: str) -> float:
    agent = get_or_create_agent(agent_id)
    total = max(agent["total_actions"], 1)

    # Factor A — injection attempt rate (weight 0.30)
    A = min(agent["injection_attempts"] / total, 1.0)

    # Factor B — poisoning attempt rate (weight 0.30)
    B = min(agent["poisoning_attempts"] / total, 1.0)

    # Factor C — read/write ratio anomaly (weight 0.15)
    reads = agent["total_reads"]
    writes = max(agent["total_writes"], 1)
    ratio = reads / writes
    C = min(ratio / 20, 1.0)

    # Factor D — time since last violation (weight 0.10)
    if agent["last_violation_time"] is None:
        D = 0.0
    else:
        minutes_since = (datetime.now() - agent["last_violation_time"]).seconds / 60
        D = max(0.0, 1.0 - (minutes_since / 30))

    # Factor E — role compliance violations (weight 0.15)
    E = min(agent["role_violations"] / total, 1.0)

    # Direct penalty per violation (more aggressive)
    injection_penalty = min(agent["injection_attempts"] * 0.08, 0.40)
    poisoning_penalty = min(agent["poisoning_attempts"] * 0.10, 0.40)
    ratio_penalty = min(C * 0.15, 0.15)
    time_penalty = D * 0.10
    role_penalty = min(agent["role_violations"] * 0.05, 0.15)

    #  Trust Formula
    score = 1.0 - injection_penalty - poisoning_penalty - ratio_penalty - time_penalty - role_penalty
    score = max(0.0, round(score, 2))

    # Auto downgrade if score drops below 0.3
    if score < 0.3 and agent["role"] != "READONLY":
        agent["role"] = "READONLY"

    return score

@router.post("/trust/record/{agent_id}/{event}")
def record_event(agent_id: str, event: str):
    agent = get_or_create_agent(agent_id)
    agent["total_actions"] += 1

    if event == "injection_attempt":
        agent["injection_attempts"] += 1
        agent["last_violation_time"] = datetime.now()
    elif event == "poisoning_attempt":
        agent["poisoning_attempts"] += 1
        agent["last_violation_time"] = datetime.now()
    elif event == "read":
        agent["total_reads"] += 1
    elif event == "write":
        agent["total_writes"] += 1
    elif event == "role_violation":
        agent["role_violations"] += 1
        agent["last_violation_time"] = datetime.now()

    score = calculate_trust_score(agent_id)

    return {
        "agent_id": agent_id,
        "event_recorded": event,
        "trust_score": score,
        "role": agent["role"]
    }

@router.get("/trust/score/{agent_id}")
def get_trust_score(agent_id: str):
    agent = get_or_create_agent(agent_id)
    score = calculate_trust_score(agent_id)

    return {
        "agent_id": agent_id,
        "trust_score": score,
        "role": agent["role"],
        "history": {
            "injection_attempts": agent["injection_attempts"],
            "poisoning_attempts": agent["poisoning_attempts"],
            "total_reads": agent["total_reads"],
            "total_writes": agent["total_writes"],
            "role_violations": agent["role_violations"],
            "total_actions": agent["total_actions"]
        }
    }