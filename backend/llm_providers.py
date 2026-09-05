"""Phase 10A — model-agnostic LLM router.

call_llm(prompt, conversation_history, provider=None) is the single place every LLM call in
SecureMem goes through (the gateway, and — reused, not duplicated — the multi-LLM evaluation
harness in testing/llm_connectors.py). Reads SECUREMEM_LLM_PROVIDER from the environment
(default "groq", the only provider with a real API key in this project). Every provider takes
the same input (prompt + history) and returns the same shape:
    {"provider": str, "model": str, "text": str}
or, if the key/package isn't available:
    {"error": "provider_not_configured", "provider": str}
so the gateway never crashes just because an operator hasn't paid for every API — per the
playbook's own note, only Groq needs to work for a live demo.
"""
import os
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


def _groq(prompt: str, history: list) -> dict:
    api_key = os.getenv("GROQ_API_KEY")
    model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    if not api_key:
        return {"error": "provider_not_configured", "provider": "groq"}
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        messages = list(history) + [{"role": "user", "content": prompt}]
        response = client.chat.completions.create(model=model, messages=messages, timeout=10.0)
        return {"provider": "groq", "model": model, "text": response.choices[0].message.content}
    except ImportError:
        return {"error": "provider_not_configured", "provider": "groq", "detail": "groq package not installed"}


def _openai(prompt: str, history: list) -> dict:
    api_key = os.getenv("OPENAI_API_KEY")
    model = "gpt-3.5-turbo"
    if not api_key:
        return {"error": "provider_not_configured", "provider": "openai"}
    try:
        import openai
        client = openai.OpenAI(api_key=api_key)
        messages = list(history) + [{"role": "user", "content": prompt}]
        response = client.chat.completions.create(model=model, messages=messages)
        return {"provider": "openai", "model": model, "text": response.choices[0].message.content}
    except ImportError:
        return {"error": "provider_not_configured", "provider": "openai", "detail": "openai package not installed"}


def _anthropic(prompt: str, history: list) -> dict:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    model = "claude-haiku-4-5-20251001"
    if not api_key:
        return {"error": "provider_not_configured", "provider": "anthropic"}
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        messages = list(history) + [{"role": "user", "content": prompt}]
        response = client.messages.create(model=model, max_tokens=1024, messages=messages)
        return {"provider": "anthropic", "model": model, "text": response.content[0].text}
    except ImportError:
        return {"error": "provider_not_configured", "provider": "anthropic", "detail": "anthropic package not installed"}


def _gemini(prompt: str, history: list) -> dict:
    api_key = os.getenv("GEMINI_API_KEY")
    model = "gemini-1.5-flash-8b"
    if not api_key:
        return {"error": "provider_not_configured", "provider": "gemini"}
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(model=model, contents=prompt)
        return {"provider": "gemini", "model": model, "text": response.text}
    except ImportError:
        return {"error": "provider_not_configured", "provider": "gemini", "detail": "google-genai package not installed"}


def _ollama(prompt: str, history: list) -> dict:
    model = "llama3"
    try:
        import httpx
        messages = list(history) + [{"role": "user", "content": prompt}]
        response = httpx.post(
            "http://localhost:11434/api/chat",
            json={"model": model, "messages": messages, "stream": False},
            timeout=10.0,
        )
        response.raise_for_status()
        data = response.json()
        return {"provider": "ollama", "model": model, "text": data.get("message", {}).get("content", "")}
    except Exception as e:
        return {"error": "provider_not_configured", "provider": "ollama", "detail": str(e)}


_PROVIDERS = {
    "groq": _groq,
    "openai": _openai,
    "anthropic": _anthropic,
    "gemini": _gemini,
    "ollama": _ollama,
}


def call_llm(prompt: str, conversation_history: Optional[list] = None, provider: Optional[str] = None) -> dict:
    provider = provider or os.getenv("SECUREMEM_LLM_PROVIDER", "groq")
    history = conversation_history or []
    handler = _PROVIDERS.get(provider)
    if handler is None:
        return {"error": "unknown_provider", "provider": provider}
    try:
        return handler(prompt, history)
    except Exception as e:
        # An unexpected error from a real API call (bad key, rate limit, etc) — never crash the
        # gateway request over it, surface it the same way as an unconfigured provider.
        return {"error": "provider_error", "provider": provider, "detail": str(e)}
