"""Target model and the authorization gate.

WP-Sentinel refuses to scan a target unless the operator has explicitly
acknowledged that they own or are authorized to test it. This is a deliberate
guardrail: the tool is for defenders and authorized auditors, not for probing
sites without permission.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse


class AuthorizationError(Exception):
    """Raised when a scan is attempted without authorization acknowledgment."""


@dataclass(frozen=True)
class Target:
    """A normalized scan target.

    Attributes:
        base_url: Normalized base URL (scheme + host [+ port], no trailing slash).
        authorized: Whether the operator confirmed permission to test this host.
    """

    base_url: str
    authorized: bool = False

    @classmethod
    def parse(cls, raw: str, *, authorized: bool = False) -> "Target":
        """Normalize a user-supplied URL into a :class:`Target`.

        Adds an ``https://`` scheme when missing, lowercases the host, and strips
        any path/query/fragment so all checks build URLs from a clean base.
        """
        candidate = raw.strip()
        if not candidate:
            raise ValueError("Target URL must not be empty.")
        if "://" not in candidate:
            candidate = "https://" + candidate

        parts = urlparse(candidate)
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported scheme: {parts.scheme!r}. Use http or https.")
        if not parts.hostname:
            raise ValueError(f"Could not parse a hostname from {raw!r}.")

        netloc = parts.hostname.lower()
        if parts.port:
            netloc = f"{netloc}:{parts.port}"

        normalized = urlunparse((parts.scheme, netloc, "", "", "", ""))
        return cls(base_url=normalized, authorized=authorized)

    def url_for(self, path: str) -> str:
        """Join a path onto the base URL."""
        return f"{self.base_url}/{path.lstrip('/')}"

    def require_authorization(self) -> None:
        """Raise :class:`AuthorizationError` unless authorization is acknowledged."""
        if not self.authorized:
            raise AuthorizationError(
                f"Refusing to scan {self.base_url}: authorization not acknowledged. "
                "Only scan systems you own or are explicitly permitted to test."
            )
