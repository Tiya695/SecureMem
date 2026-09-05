"""Phase 3 auth/RBAC tests. Requires a live server: uvicorn backend.main:app --port 8000

Matches the existing style in tests/test_memory.py and tests/test_sdk.py — real HTTP calls
against a running instance, no mocking.
"""
import os
import time
import uuid
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
from jose import jwt

load_dotenv()

BASE_URL = "http://127.0.0.1:8000"
JWT_SECRET = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"


def _agent_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _token(agent_id: str, role: str, admin_secret: str | None = None) -> str:
    payload = {"agent_id": agent_id, "role": role}
    if admin_secret is not None:
        payload["admin_secret"] = admin_secret
    resp = requests.post(f"{BASE_URL}/auth/token", json=payload, timeout=5)
    resp.raise_for_status()
    return resp.json()["access_token"]


def test_agent_cannot_self_escalate_to_admin():
    """An AGENT cannot mint themselves an ADMIN token without the bootstrap secret."""
    resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"agent_id": _agent_id("escalator"), "role": "ADMIN"},
        timeout=5,
    )
    assert resp.status_code == 403, resp.text

    # A wrong guess at the secret must also fail.
    resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"agent_id": _agent_id("escalator"), "role": "ADMIN", "admin_secret": "not-the-secret"},
        timeout=5,
    )
    assert resp.status_code == 403, resp.text


def test_readonly_cannot_write():
    agent = _agent_id("readonly_agent")
    token = _token(agent, "READONLY")
    resp = requests.post(
        f"{BASE_URL}/memory/write",
        json={"agent_id": agent, "content": "should not be stored", "namespace": agent},
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert resp.status_code == 403, resp.text


def test_expired_jwt_rejected():
    agent = _agent_id("expired_agent")
    expired_payload = {
        "agent_id": agent,
        "role": "AGENT",
        "exp": datetime.utcnow() - timedelta(minutes=5),
    }
    expired_token = jwt.encode(expired_payload, JWT_SECRET, algorithm=ALGORITHM)
    resp = requests.get(
        f"{BASE_URL}/memory/search",
        params={"agent_id": agent, "query": "test", "namespace": agent},
        headers={"Authorization": f"Bearer {expired_token}"},
        timeout=5,
    )
    assert resp.status_code == 401, resp.text


def test_agent_a_cannot_access_agent_b_namespace():
    agent_a = _agent_id("agent_a")
    agent_b = _agent_id("agent_b")
    token_a = _token(agent_a, "AGENT")

    resp = requests.post(
        f"{BASE_URL}/memory/write",
        json={"agent_id": agent_a, "content": "cross-namespace attempt", "namespace": agent_b},
        headers={"Authorization": f"Bearer {token_a}"},
        timeout=5,
    )
    assert resp.status_code == 403, resp.text

    resp = requests.get(
        f"{BASE_URL}/memory/search",
        params={"agent_id": agent_a, "query": "test", "namespace": agent_b},
        headers={"Authorization": f"Bearer {token_a}"},
        timeout=5,
    )
    assert resp.status_code == 403, resp.text


def test_unauthenticated_request_rejected():
    agent = _agent_id("no_auth_agent")
    resp = requests.post(
        f"{BASE_URL}/memory/write",
        json={"agent_id": agent, "content": "no token supplied", "namespace": agent},
        timeout=5,
    )
    assert resp.status_code == 401, resp.text
