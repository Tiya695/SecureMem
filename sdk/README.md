# SecureMem SDK

A simple Python client for the SecureMem Protocol — secure, namespace-isolated, encrypted memory
for multi-agent AI systems.

## Installation

Copy `securemem_sdk.py` into your project, or import it directly (it only requires `httpx`):

```bash
pip install httpx
```

## Quick Start

```python
from securemem_sdk import SecureMemClient, AccessDeniedError, NotFoundError

# Connect as an AGENT — automatically authenticates and gets a token
client = SecureMemClient(
    base_url="http://127.0.0.1:8000",
    agent_id="my_agent",
    role="AGENT"
)

# Write a memory
memory_id = client.write_memory(
    content="User prefers dark mode",
    namespace="my_agent_personal"
)
print("Stored:", memory_id)

# Search memories
results = client.search_memory(
    query="What are the user's UI preferences?",
    namespace="my_agent_personal",
    top_k=3
)
for r in results:
    print(r["content"])

# Delete a memory
client.delete_memory(memory_id)
```

## Protecting an existing LLM app in one line

```python
check = client.protect(user_input)
if not check["safe"]:
    print("Blocked:", check["reason"])
else:
    call_your_llm(user_input)
```

`protect()` runs a prompt through the full SecureMem security pipeline (firewall, PII, poison,
policy engine, Investigator Agent) without writing anything or calling an LLM itself — see
`examples/basic_python_app.py` and `examples/securemem_openai.py` for complete integration
examples.

## Roles

| Role     | Can Write/Delete | Can Search        |
|----------|-------------------|-------------------|
| ADMIN    | Any namespace      | Any namespace      |
| AGENT    | Own namespace only | Own namespace only |
| READONLY | No                 | Own namespace only |

A namespace "belongs" to an agent if it equals the `agent_id` or starts with `{agent_id}_`
(e.g., `my_agent_personal`). Minting an ADMIN-role token requires `admin_secret` to match the
server's `ADMIN_BOOTSTRAP_SECRET`:

```python
admin = SecureMemClient(base_url="http://127.0.0.1:8000", agent_id="admin_user", role="ADMIN",
                         admin_secret="the-server's-ADMIN_BOOTSTRAP_SECRET")
```

## Error Handling

```python
try:
    client.search_memory("query", namespace="someone_elses_namespace")
except AccessDeniedError as e:
    print("Blocked by RBAC:", e)
except AuthenticationError as e:
    print("Auth problem:", e)
except NotFoundError as e:
    print("Not found:", e)
except SecureMemError as e:
    print("Other error:", e)
```

## Methods

- `connect(base_url, agent_id, role="AGENT", admin_secret=None) -> SecureMemClient` — module-level
  convenience constructor.
- `protect(prompt) -> {safe, reason, confidence, attack_type}` — security-check only, no LLM call.
- `write_memory(content, namespace, metadata=None) -> memory_id`
- `search_memory(query, namespace, top_k=5) -> list of matches`
- `delete_memory(memory_id) -> bool`
- `rollback_memory(memory_id, version) -> dict` — ADMIN role only.
- `get_trust_score() -> dict`
