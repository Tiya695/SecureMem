"""Ensures the project root is importable (e.g. `from firewall.x import y`, `from memory.x import y`)
regardless of how pytest is invoked. Without this, only test files that manually sys.path-hack
(like test_sdk.py did for the sdk/ package) can import project packages.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
