import httpx


class SecureMemError(Exception):
    """Base exception for all SecureMem SDK errors."""
    pass


class AuthenticationError(SecureMemError):
    """Raised when authentication fails (401)."""
    pass


class AccessDeniedError(SecureMemError):
    """Raised when an action is forbidden by RBAC (403)."""
    pass


class NotFoundError(SecureMemError):
    """Raised when a requested resource does not exist (404)."""
    pass


class SecureMemClient:
    """
    Client for the SecureMem Protocol.

    Example:
        client = SecureMemClient("http://127.0.0.1:8002", agent_id="agent_A", role="AGENT")
        mem_id = client.write_memory("User likes tea", namespace="agent_A_personal")
        results = client.search_memory("What drinks?", namespace="agent_A_personal")
    """

    def __init__(self, base_url: str, agent_id: str, role: str, trust_base_url: str = None):
        self.base_url = base_url.rstrip("/")
        self.trust_base_url = (trust_base_url or base_url).rstrip("/")
        self.agent_id = agent_id
        self.role = role
        self.token = self._get_token()

    def _get_token(self) -> str:
        response = httpx.post(f"{self.base_url}/auth/token", json={
            "agent_id": self.agent_id,
            "role": self.role
        })
        if response.status_code != 200:
            raise AuthenticationError(f"Failed to obtain token: {response.text}")
        return response.json()["access_token"]

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def _handle_errors(self, response: httpx.Response):
        if response.status_code == 401:
            raise AuthenticationError(response.json().get("detail", "Unauthorized"))
        if response.status_code == 403:
            raise AccessDeniedError(response.json().get("detail", "Access denied"))
        if response.status_code == 404:
            raise NotFoundError(response.json().get("detail", "Not found"))
        if response.status_code >= 400:
            raise SecureMemError(f"Request failed ({response.status_code}): {response.text}")

    def write_memory(self, content: str, namespace: str, metadata: dict = None) -> str:
        response = httpx.post(
            f"{self.base_url}/memory/write",
            headers=self._headers(),
            json={
                "agent_id": self.agent_id,
                "content": content,
                "namespace": namespace,
                "metadata": metadata or {}
            }
        )
        self._handle_errors(response)
        return response.json()["id"]

    def search_memory(self, query: str, namespace: str, top_k: int = 5) -> list:
        response = httpx.get(
            f"{self.base_url}/memory/search",
            headers=self._headers(),
            params={
                "agent_id": self.agent_id,
                "query": query,
                "namespace": namespace,
                "top_k": top_k
            }
        )
        self._handle_errors(response)
        return response.json()["matches"]

    def delete_memory(self, memory_id: str) -> bool:
        response = httpx.request(
            "DELETE",
            f"{self.base_url}/memory/delete",
            headers=self._headers(),
            json={"memory_id": memory_id}
        )
        self._handle_errors(response)
        return response.json()["status"] == "deleted"

    def get_trust_score(self) -> dict:
        response = httpx.get(f"{self.trust_base_url}/trust/score/{self.agent_id}")
        self._handle_errors(response)
        return response.json()