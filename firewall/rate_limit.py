"""Shared slowapi Limiter instance.

A single Limiter must be shared across backend/main.py and memory/api.py (and any future
router modules) so that rate-limit state and the exception handler registered on the FastAPI
app apply consistently everywhere `@limiter.limit(...)` is used.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
