\# RBAC Test Results



\## Test 1: READONLY role cannot write

\- \*\*Action:\*\* Generated a READONLY token for `agent\_A`, attempted `POST /memory/write`

\- \*\*Expected:\*\* 403 Forbidden

\- \*\*Actual:\*\* `{"detail":"Access denied: READONLY role cannot write or delete"}`

\- \*\*Result:\*\* PASS ✅



\## Test 2: AGENT role cannot access another agent's namespace

\- \*\*Action:\*\* Generated an AGENT token for `agent\_A`, attempted `GET /memory/search` on `agent\_B\_personal` namespace

\- \*\*Expected:\*\* 403 Forbidden

\- \*\*Actual:\*\* `{"detail":"Access denied: this namespace does not belong to you"}`

\- \*\*Result:\*\* PASS ✅



\## Test 3: ADMIN role can access any namespace

\- \*\*Action:\*\* Generated an ADMIN token for `admin\_user`, performed `POST /memory/write` into `agent\_B\_personal` namespace

\- \*\*Expected:\*\* 200 OK, memory stored successfully

\- \*\*Actual:\*\* `{"status":"stored","id":"6e7ceef4-7c11-4bc1-98ac-391bce33637f"}`

\- \*\*Result:\*\* PASS ✅



\## Conclusion

All three RBAC rules (READONLY restriction, AGENT namespace isolation, ADMIN full access) function correctly as designed. Authentication is implemented using JWT tokens (HS256), issued via `POST /auth/token`, and verified on every protected endpoint via a FastAPI dependency.

