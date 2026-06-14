\# SecureMem SDK



A simple Python client for the SecureMem Protocol — secure, namespace-isolated,

encrypted memory for multi-agent AI systems.



\## Installation



Copy `securemem\_sdk.py` into your project, or import it directly (it only

requires `httpx`):



```bash

pip install httpx

```



\## Quick Start



```python

from securemem\_sdk import SecureMemClient, AccessDeniedError, NotFoundError



\# Connect as an AGENT — automatically authenticates and gets a token

client = SecureMemClient(

&#x20;   base\_url="http://127.0.0.1:8002",

&#x20;   agent\_id="my\_agent",

&#x20;   role="AGENT"

)



\# Write a memory

memory\_id = client.write\_memory(

&#x20;   content="User prefers dark mode",

&#x20;   namespace="my\_agent\_personal"

)

print("Stored:", memory\_id)



\# Search memories

results = client.search\_memory(

&#x20;   query="What are the user's UI preferences?",

&#x20;   namespace="my\_agent\_personal",

&#x20;   top\_k=3

)

for r in results:

&#x20;   print(r\["content"])



\# Delete a memory

client.delete\_memory(memory\_id)

```



\## Roles



| Role     | Can Write/Delete | Can Search        |

|----------|-------------------|-------------------|

| ADMIN    | Any namespace      | Any namespace      |

| AGENT    | Own namespace only | Own namespace only |

| READONLY | No                 | Own namespace only |



A namespace "belongs" to an agent if it equals the `agent\_id` or starts with

`{agent\_id}\_` (e.g., `my\_agent\_personal`).



\## Error Handling



```python

try:

&#x20;   client.search\_memory("query", namespace="someone\_elses\_namespace")

except AccessDeniedError as e:

&#x20;   print("Blocked by RBAC:", e)

except AuthenticationError as e:

&#x20;   print("Auth problem:", e)

except NotFoundError as e:

&#x20;   print("Not found:", e)

except SecureMemError as e:

&#x20;   print("Other error:", e)

```



\## Methods



\- `write\_memory(content, namespace, metadata=None) -> memory\_id`

\- `search\_memory(query, namespace, top\_k=5) -> list of matches`

\- `delete\_memory(memory\_id) -> bool`

\- `get\_trust\_score() -> dict` (requires the trust engine API, e.g., port 8000)

