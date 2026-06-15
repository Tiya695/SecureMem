from fastapi import Header, HTTPException
from jose import jwt, JWTError
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
EXPIRE_MINUTES = 60


def create_access_token(agent_id: str, role: str) -> str:
    payload = {
        "agent_id": agent_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=EXPIRE_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def get_current_agent(authorization: str = Header(None)):
    """Reads 'Authorization: Bearer <token>' header and returns {agent_id, role}."""
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return {"agent_id": payload["agent_id"], "role": payload["role"]}


def check_namespace_access(current_agent: dict, namespace: str):
    """ADMIN can access any namespace. AGENT/READONLY only their own (namespace must start with their agent_id)."""
    role = current_agent["role"]
    agent_id = current_agent["agent_id"]

    if role == "ADMIN":
        return

    if not (namespace == agent_id or namespace.startswith(f"{agent_id}_")):
        raise HTTPException(status_code=403, detail="Access denied: this namespace does not belong to you")


def check_write_permission(current_agent: dict):
    """READONLY role cannot write or delete."""
    if current_agent["role"] == "READONLY":
        raise HTTPException(status_code=403, detail="Access denied: READONLY role cannot write or delete")