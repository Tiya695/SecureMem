\# SecureMem Protocol Specification



Version 1.0



\## 1. What is the SecureMem Protocol?



SecureMem is a protocol for secure, multi-agent AI memory systems. It defines

a standard contract for how AI agents authenticate, store ("write"), retrieve

("search"), and remove ("delete") memories — while enforcing namespace

isolation, role-based access control, and encryption at rest.



Any client (regardless of programming language) that sends requests in the

formats described below, and handles the documented responses and error

codes, is considered "SecureMem-compatible."



Base URL (local development): `http://127.0.0.1:8002`



\## 2. Authentication Flow



All memory endpoints require a JWT (JSON Web Token) sent in the

`Authorization` header as: `Authorization: Bearer <token>`



\### Obtaining a token



\*\*Endpoint:\*\* `POST /auth/token`



\*\*Request body:\*\*

```json

{

&#x20; "agent\_id": "string",

&#x20; "role": "ADMIN | AGENT | READONLY"

}

```



\*\*Response (200):\*\*

```json

{

&#x20; "access\_token": "string (JWT)",

&#x20; "token\_type": "bearer",

&#x20; "agent\_id": "string",

&#x20; "role": "string"

}

```



Tokens are signed using HS256 and expire after 60 minutes.



\### Roles



| Role     | Permissions                                              |

|----------|-----------------------------------------------------------|

| ADMIN    | Read, write, delete in ANY namespace                       |

| AGENT    | Read, write, delete ONLY in namespaces matching their own agent\_id |

| READONLY | Search only, in their own namespace; write/delete blocked  |



\## 3. Memory Write Specification



\*\*Endpoint:\*\* `POST /memory/write`

\*\*Auth required:\*\* Yes (ADMIN or AGENT — not READONLY)



\*\*Request body:\*\*

```json

{

&#x20; "agent\_id": "string",

&#x20; "content": "string",

&#x20; "namespace": "string",

&#x20; "metadata": {}

}

```



\*\*Process:\*\*

1\. Token is verified; role checked (must not be READONLY)

2\. Namespace ownership checked (ADMIN bypasses this)

3\. `content` is converted to a 384-dimension embedding using `all-MiniLM-L6-v2`

4\. `content` is encrypted (Fernet/AES) before storage

5\. Record stored in PostgreSQL with pgvector



\*\*Response (200):\*\*

```json

{

&#x20; "status": "stored",

&#x20; "id": "uuid-string"

}

```



\## 4. Memory Search Specification



\*\*Endpoint:\*\* `GET /memory/search`

\*\*Auth required:\*\* Yes (any role)



\*\*Query parameters:\*\*

| Parameter | Type   | Default | Description                          |

|-----------|--------|---------|--------------------------------------|

| agent\_id  | string | -       | Requesting agent's ID                |

| query     | string | -       | Natural language search query        |

| namespace | string | -       | Namespace to search within            |

| top\_k     | int    | 5       | Number of results to return           |



\*\*Process:\*\*

1\. Token verified; namespace ownership checked (ADMIN bypasses)

2\. `query` converted to embedding

3\. Cosine similarity search against stored embeddings in `namespace`

4\. Top `top\_k` results returned, content decrypted



\*\*Response (200):\*\*

```json

{

&#x20; "matches": \[

&#x20;   {"id": "uuid-string", "content": "string", "agent\_id": "string"}

&#x20; ]

}

```



\## 5. Memory Delete Specification



\*\*Endpoint:\*\* `DELETE /memory/delete`

\*\*Auth required:\*\* Yes (ADMIN or AGENT — not READONLY)



\*\*Request body:\*\*

```json

{

&#x20; "memory\_id": "uuid-string"

}

```



\*\*Process:\*\*

1\. Token verified; role checked (must not be READONLY)

2\. Memory looked up by ID; if not found, 404 returned

3\. Namespace ownership of the found memory checked (ADMIN bypasses)

4\. Record permanently deleted



\*\*Response (200):\*\*

```json

{

&#x20; "status": "deleted",

&#x20; "id": "uuid-string"

}

```



\## 6. Trust Score Specification



Trust scores track agent behaviour and automatically downgrade misbehaving

agents to READONLY when trust drops below 0.3.



\*\*Record an event:\*\* `POST /trust/record/{agent\_id}/{event}`

Where `event` is one of: `injection\_attempt`, `poisoning\_attempt`, `read`,

`write`, `role\_violation`



\*\*Response (200):\*\*

```json

{

&#x20; "agent\_id": "string",

&#x20; "event\_recorded": "string",

&#x20; "trust\_score": 0.0,

&#x20; "role": "string"

}

```



\*\*Get current score:\*\* `GET /trust/score/{agent\_id}`



\*\*Response (200):\*\*

```json

{

&#x20; "agent\_id": "string",

&#x20; "trust\_score": 0.0,

&#x20; "role": "string",

&#x20; "history": {

&#x20;   "injection\_attempts": 0,

&#x20;   "poisoning\_attempts": 0,

&#x20;   "total\_reads": 0,

&#x20;   "total\_writes": 0,

&#x20;   "role\_violations": 0,

&#x20;   "total\_actions": 0

&#x20; }

}

```



\## 7. Error Code Reference



| Code | Meaning              | When it occurs                                              |

|------|----------------------|--------------------------------------------------------------|

| 400  | Bad Request          | Invalid role value sent to `/auth/token`                      |

| 401  | Unauthorized         | Missing, malformed, or expired JWT token                       |

| 403  | Forbidden            | READONLY attempting write/delete, or AGENT accessing another agent's namespace |

| 404  | Not Found            | `memory\_id` does not exist (delete)                            |

| 422  | Unprocessable Entity | Request body fails validation (e.g., missing required field)  |

| 500  | Internal Server Error| Unexpected server-side error                                   |

