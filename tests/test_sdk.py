import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

import pytest
from securemem_sdk import SecureMemClient, AccessDeniedError

BASE_URL = "http://127.0.0.1:8002"


def test_sdk_write_and_search():
    agent_a = SecureMemClient(BASE_URL, agent_id="sdk_agent_A", role="AGENT")

    agent_a.write_memory("User likes tea", "sdk_agent_A_personal")
    agent_a.write_memory("User likes coffee", "sdk_agent_A_personal")
    agent_a.write_memory("User dislikes soda", "sdk_agent_A_personal")

    results = agent_a.search_memory("What drinks does the user like?", "sdk_agent_A_personal", top_k=3)
    assert len(results) == 3


def test_sdk_namespace_isolation():
    agent_a = SecureMemClient(BASE_URL, agent_id="sdk_agent_A", role="AGENT")
    agent_b = SecureMemClient(BASE_URL, agent_id="sdk_agent_B", role="AGENT")

    agent_a.write_memory("Agent A's private note about the budget", "sdk_agent_A_personal")

    with pytest.raises(AccessDeniedError):
        agent_b.search_memory("private note", "sdk_agent_A_personal")