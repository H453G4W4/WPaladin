"""HTTP API and browser dashboard for WP-Sentinel.

The API is a thin layer over :class:`wp_sentinel.core.scanner.Scanner`. It
requires the optional ``[api]`` dependencies (FastAPI + uvicorn).
"""

from .app import create_app

__all__ = ["create_app"]
