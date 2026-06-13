from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

router = APIRouter()

# In-memory provenance log (acts like a database table for now)
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

@router.post("/provenance/log")
def add_log(request: LogRequest):
    log_entry = {
        "operation": request.operation,
        "memory_id": request.memory_id,
        "agent_id": request.agent_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "outcome": request.outcome
    }
    provenance_logs.append(log_entry)
    return {"message": "Log recorded", "log": log_entry}

@router.get("/provenance/logs")
def get_logs():
    # Return last 100 logs (ADMIN view)
    return {
        "total": len(provenance_logs),
        "logs": provenance_logs[-100:]
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