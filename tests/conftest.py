"""Shared test helpers: a routable mock HTTP transport."""

from __future__ import annotations

from typing import Callable

import httpx
import pytest


class MockSite:
    """Builds an httpx MockTransport from a routing table.

    Routes are keyed by ``(method, path)`` where path includes the query string
    (e.g. ``/?author=1``). Unmatched requests return 404.
    """

    def __init__(self) -> None:
        self._routes: dict[tuple[str, str], httpx.Response] = {}

    def add(
        self,
        path: str,
        *,
        status: int = 200,
        text: str = "",
        headers: dict[str, str] | None = None,
        method: str = "GET",
    ) -> "MockSite":
        self._routes[(method.upper(), path)] = httpx.Response(
            status_code=status, text=text, headers=headers or {}
        )
        return self

    def _handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode()
        # Normalize root "/" so tests can register base URL as "/".
        key = (request.method, path)
        if key in self._routes:
            return self._routes[key]
        # Try without trailing normalization for the homepage.
        if path in ("", "/"):
            for candidate in ("/", ""):
                alt = (request.method, candidate)
                if alt in self._routes:
                    return self._routes[alt]
        return httpx.Response(404, text="not found")

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handler)


@pytest.fixture
def mock_site() -> Callable[[], MockSite]:
    return MockSite


@pytest.fixture(autouse=True)
def _offline_tls(monkeypatch):
    """Keep the TLS check hermetic.

    ``TlsCheck`` opens a raw socket, which would otherwise make real network
    calls during scanner/API tests. Stub the probe with a healthy result
    (modern protocol, far-future cert) so it produces no findings unless a test
    overrides it. Dedicated TLS tests re-patch ``_probe`` for their scenario.
    """
    import datetime as dt

    from wp_sentinel.checks.tls import TlsCheck, _TlsInfo

    def healthy(host, port, timeout):
        return _TlsInfo(
            protocol="TLSv1.3",
            not_after=dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc),
        )

    monkeypatch.setattr(TlsCheck, "_probe", staticmethod(healthy))
