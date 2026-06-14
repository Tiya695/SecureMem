import httpx

BASE_URL = "http://127.0.0.1:8002"


def test_namespace_isolation():
    # Agent A writes a memory in its own namespace
    httpx.post(f"{BASE_URL}/memory/write", json={
        "agent_id": "test_agent_A",
        "content": "Secret project deadline is Friday",
        "namespace": "test_A_namespace",
        "metadata": {}
    })

    # Agent B searches in Agent A's namespace - should find nothing relevant to B
    response = httpx.get(f"{BASE_URL}/memory/search", params={
        "agent_id": "test_agent_B",
        "query": "What is the secret deadline?",
        "namespace": "test_B_namespace",
        "top_k": 5
    })
    matches = response.json()["matches"]
    contents = [m["content"] for m in matches]
    assert "Secret project deadline is Friday" not in contents


def test_semantic_search_relevance():
    httpx.post(f"{BASE_URL}/memory/write", json={
        "agent_id": "test_agent_C",
        "content": "The user's favorite hobby is painting landscapes",
        "namespace": "test_C_namespace",
        "metadata": {}
    })

    response = httpx.get(f"{BASE_URL}/memory/search", params={
        "agent_id": "test_agent_C",
        "query": "What does the user enjoy doing for fun?",
        "namespace": "test_C_namespace",
        "top_k": 1
    })
    matches = response.json()["matches"]
    assert len(matches) == 1
    assert "painting" in matches[0]["content"]


def test_deleted_memory_not_returned():
    # Write a memory
    write_response = httpx.post(f"{BASE_URL}/memory/write", json={
        "agent_id": "test_agent_D",
        "content": "Temporary memory to be deleted",
        "namespace": "test_D_namespace",
        "metadata": {}
    })
    memory_id = write_response.json()["id"]

    # Delete it
    httpx.request("DELETE", f"{BASE_URL}/memory/delete", json={"memory_id": memory_id})

    # Search - should not find it
    response = httpx.get(f"{BASE_URL}/memory/search", params={
        "agent_id": "test_agent_D",
        "query": "Temporary memory to be deleted",
        "namespace": "test_D_namespace",
        "top_k": 5
    })
    matches = response.json()["matches"]
    ids = [m["id"] for m in matches]
    assert memory_id not in ids