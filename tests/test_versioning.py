"""Phase 7 memory versioning & rollback tests. Requires a live server AND a running Postgres
instance behind DATABASE_URL (see docs/PROJECT_AUDIT.md for how to stand one up locally).
"""
import os
import uuid
import requests
from dotenv import load_dotenv

load_dotenv()
BASE_URL = "http://127.0.0.1:8000"


def _agent_token(agent_id: str, role: str = "AGENT") -> str:
    payload = {"agent_id": agent_id, "role": role}
    if role == "ADMIN":
        payload["admin_secret"] = os.getenv("ADMIN_BOOTSTRAP_SECRET")
    return requests.post(f"{BASE_URL}/auth/token", json=payload, timeout=5).json()["access_token"]


def test_write_creates_version_one():
    agent = f"ver_agent_{uuid.uuid4().hex[:8]}"
    token = _agent_token(agent)
    admin_token = _agent_token("admin_ver_test", "ADMIN")

    write = requests.post(
        f"{BASE_URL}/memory/write",
        json={"agent_id": agent, "content": "The deploy window is Tuesday", "namespace": agent},
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert write.status_code == 200, write.text
    memory_id = write.json()["id"]

    history = requests.get(
        f"{BASE_URL}/memory/{memory_id}/history",
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5,
    )
    assert history.status_code == 200, history.text
    versions = history.json()["versions"]
    assert len(versions) == 1
    assert versions[0]["version_number"] == 1
    assert versions[0]["operation"] == "create"


def test_update_creates_new_version_and_rollback_restores_original():
    agent = f"ver_agent_{uuid.uuid4().hex[:8]}"
    token = _agent_token(agent)
    admin_token = _agent_token("admin_ver_test2", "ADMIN")
    headers = {"Authorization": f"Bearer {token}"}

    write = requests.post(
        f"{BASE_URL}/memory/write",
        json={"agent_id": agent, "content": "Original safe content", "namespace": agent},
        headers=headers, timeout=5,
    )
    memory_id = write.json()["id"]

    update = requests.post(
        f"{BASE_URL}/memory/{memory_id}/update",
        json={"content": "Updated content, still safe", "change_reason": "test update"},
        headers=headers, timeout=5,
    )
    assert update.status_code == 200, update.text
    assert update.json()["version"] == 2

    search = requests.get(
        f"{BASE_URL}/memory/search",
        params={"agent_id": agent, "query": "updated content", "namespace": agent, "top_k": 1},
        headers=headers, timeout=5,
    )
    assert "Updated content" in search.json()["matches"][0]["content"]

    # Roll back to version 1 (ADMIN only).
    rollback = requests.post(
        f"{BASE_URL}/memory/{memory_id}/rollback/1",
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5,
    )
    assert rollback.status_code == 200, rollback.text
    assert rollback.json()["new_version"] == 3  # rollback itself is a new version, not a delete

    search_after = requests.get(
        f"{BASE_URL}/memory/search",
        params={"agent_id": agent, "query": "original safe content", "namespace": agent, "top_k": 1},
        headers=headers, timeout=5,
    )
    assert "Original safe content" in search_after.json()["matches"][0]["content"]

    history = requests.get(
        f"{BASE_URL}/memory/{memory_id}/history",
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5,
    )
    ops = [v["operation"] for v in history.json()["versions"]]
    assert ops == ["create", "update", "rollback"]


def test_history_and_rollback_require_admin():
    agent = f"ver_agent_{uuid.uuid4().hex[:8]}"
    token = _agent_token(agent)

    write = requests.post(
        f"{BASE_URL}/memory/write",
        json={"agent_id": agent, "content": "some content", "namespace": agent},
        headers={"Authorization": f"Bearer {token}"}, timeout=5,
    )
    memory_id = write.json()["id"]

    history = requests.get(
        f"{BASE_URL}/memory/{memory_id}/history",
        headers={"Authorization": f"Bearer {token}"}, timeout=5,
    )
    assert history.status_code == 403

    rollback = requests.post(
        f"{BASE_URL}/memory/{memory_id}/rollback/1",
        headers={"Authorization": f"Bearer {token}"}, timeout=5,
    )
    assert rollback.status_code == 403


def test_rollback_nonexistent_version_404s():
    agent = f"ver_agent_{uuid.uuid4().hex[:8]}"
    token = _agent_token(agent)
    admin_token = _agent_token("admin_ver_test3", "ADMIN")

    write = requests.post(
        f"{BASE_URL}/memory/write",
        json={"agent_id": agent, "content": "some content", "namespace": agent},
        headers={"Authorization": f"Bearer {token}"}, timeout=5,
    )
    memory_id = write.json()["id"]

    rollback = requests.post(
        f"{BASE_URL}/memory/{memory_id}/rollback/99",
        headers={"Authorization": f"Bearer {admin_token}"}, timeout=5,
    )
    assert rollback.status_code == 404
