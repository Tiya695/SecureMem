"""Ensures the project root is importable (e.g. `from firewall.x import y`, `from memory.x import y`)
regardless of how pytest is invoked. Without this, only test files that manually sys.path-hack
(like test_sdk.py did for the sdk/ package) can import project packages.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_URL = "http://127.0.0.1:8000"


@pytest.fixture(scope="session")
def admin_token():
    """One ADMIN token minted for the whole test session, instead of every test file minting
    its own. Individual test files still mint their own AGENT/READONLY tokens where per-test
    isolation matters (different agent_id per test), but nearly every file also needs an ADMIN
    token just to hit one gated endpoint — repeating that across dozens of tests is what pushed
    /auth/token's call volume past its own rate limit when running the full suite (see
    docs/AUTH_AUDIT.md). New tests needing ADMIN access should prefer this fixture."""
    import requests
    from dotenv import load_dotenv
    load_dotenv()
    resp = requests.post(
        f"{BASE_URL}/auth/token",
        json={"agent_id": "session_admin_fixture", "role": "ADMIN", "admin_secret": os.getenv("ADMIN_BOOTSTRAP_SECRET")},
        timeout=10,
    )
    return resp.json()["access_token"]


def pytest_collection_modifyitems(session, config, items):
    """test_attack_rate_limit_abuse intentionally exhausts /firewall/check's shared per-IP rate
    limit bucket (slowapi's state lives for the life of the server process, not reset per test).
    Every test in the suite runs from this same machine/IP, so if that test runs anywhere but
    last, it 429s whatever /firewall/check call happens to run next — in this file or another.
    Force it to run dead last regardless of collection order."""
    def is_rate_limit_abuse_test(item):
        return item.name == "test_attack_rate_limit_abuse"

    items.sort(key=is_rate_limit_abuse_test)
