"""Async HTTP client with polite rate limiting.

Wraps ``httpx.AsyncClient`` to enforce a per-scan concurrency cap and a minimum
inter-request delay. A single, honest User-Agent is used by default; WP-Sentinel
does **not** rotate user-agents or spoof browser fingerprints to evade
detection. Identifying yourself is the responsible default for an authorized
security tool.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from .profile import Profile
from .. import __version__

DEFAULT_USER_AGENT = f"WP-Sentinel/{__version__} (+authorized security audit)"


@dataclass
class Response:
    """A minimal, framework-agnostic view of an HTTP response."""

    status_code: int
    url: str
    headers: dict[str, str]
    text: str

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup."""
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None


class RateLimitedClient:
    """A politeness-enforcing wrapper around an httpx async client.

    Requests are gated by a semaphore (concurrency) and a shared clock that
    guarantees ``delay_seconds`` between request starts.
    """

    def __init__(
        self,
        profile: Profile,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self._profile = profile
        self._semaphore = asyncio.Semaphore(profile.concurrency)
        self._delay = profile.delay_seconds
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=profile.timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": user_agent},
        )

    async def __aenter__(self) -> "RateLimitedClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _throttle(self) -> None:
        """Enforce the minimum inter-request delay using the event loop clock."""
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            wait = self._next_allowed - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = loop.time()
            self._next_allowed = now + self._delay

    async def request(self, method: str, url: str, **kwargs: Any) -> Response | None:
        """Perform a request, returning ``None`` on network/timeout errors.

        Returning ``None`` (rather than raising) lets individual checks treat an
        unreachable endpoint as "no finding" instead of aborting the whole scan.
        """
        async with self._semaphore:
            await self._throttle()
            try:
                resp = await self._client.request(method, url, **kwargs)
            except httpx.HTTPError:
                return None
        return Response(
            status_code=resp.status_code,
            url=str(resp.url),
            headers=dict(resp.headers),
            text=resp.text,
        )

    async def get(self, url: str, **kwargs: Any) -> Response | None:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Response | None:
        return await self.request("HEAD", url, **kwargs)
