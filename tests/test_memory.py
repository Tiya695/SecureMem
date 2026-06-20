import httpx

BASE_URL = "http://127.0.0.1:8000"


def get_admin_token():
    response = httpx.post(f"{BASE_URL}/auth/token", json={
        "agent_id": "test_admin",
        "role": "ADMIN"
    })
    return response.json()["access_token"]


HEADERS = {"Authorization": f"Bearer {get_admin_token()}"}


def test_namespace_isolation():
    httpx.post(f"{BASE_URL}/memory/write", headers=HEADERS, json={
        "agent_id": "test_agent_A",
        "content": "Secret project deadline is Friday",
        "namespace": "test_A_namespace",
        "metadata": {}
    })

    response = httpx.get(f"{BASE_URL}/memory/search", headers=HEADERS, params={
        "agent_id": "test_agent_B",
        "query": "What is the secret deadline?",
        "namespace": "test_B_namespace",
        "top_k": 5
    })
    matches = response.json()["matches"]
    contents = [m["content"] for m in matches]
    assert "Secret project deadline is Friday" not in contents


def test_semantic_search_relevance():
    httpx.post(f"{BASE_URL}/memory/write", headers=HEADERS, json={
        "agent_id": "test_agent_C",
        "content": "The user's favorite hobby is painting landscapes",
        "namespace": "test_C_namespace",
        "metadata": {}
    })

    response = httpx.get(f"{BASE_URL}/memory/search", headers=HEADERS, params={
        "agent_id": "test_agent_C",
        "query": "What does the user enjoy doing for fun?",
        "namespace": "test_C_namespace",
        "top_k": 1
    })
    matches = response.json()["matches"]
    assert len(matches) == 1
    assert "painting" in matches[0]["content"]


def test_deleted_memory_not_returned():
    write_response = httpx.post(f"{BASE_URL}/memory/write", headers=HEADERS, json={
        "agent_id": "test_agent_D",
        "content": "Temporary memory to be deleted",
        "namespace": "test_D_namespace",
        "metadata": {}
    })
    memory_id = write_response.json()["id"]

    httpx.request("DELETE", f"{BASE_URL}/memory/delete", headers=HEADERS, json={"memory_id": memory_id})

    response = httpx.get(f"{BASE_URL}/memory/search", headers=HEADERS, params={
        "agent_id": "test_agent_D",
        "query": "Temporary memory to be deleted",
        "namespace": "test_D_namespace",
        "top_k": 5
    })
    matches = response.json()["matches"]
    ids = [m["id"] for m in matches]
    assert memory_id not in ids


def test_readonly_cannot_write():
    token = httpx.post(f"{BASE_URL}/auth/token", json={
        "agent_id": "agent_RO",
        "role": "READONLY"
    }).json()["access_token"]

    response = httpx.post(f"{BASE_URL}/memory/write", headers={"Authorization": f"Bearer {token}"}, json={
        "agent_id": "agent_RO",
        "content": "Should not be allowed",
        "namespace": "agent_RO_personal",
        "metadata": {}
    })
    assert response.status_code == 403


def test_agent_cannot_access_other_namespace():
    token = httpx.post(f"{BASE_URL}/auth/token", json={
        "agent_id": "agent_X",
        "role": "AGENT"
    }).json()["access_token"]

    response = httpx.get(f"{BASE_URL}/memory/search", headers={"Authorization": f"Bearer {token}"}, params={
        "agent_id": "agent_X",
        "query": "anything",
        "namespace": "agent_Y_personal",
        "top_k": 5
    })
    assert response.status_code == 403