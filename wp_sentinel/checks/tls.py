"""TLS/SSL configuration analysis.

Inspects the target's certificate and negotiated protocol without sending any
application data. Flags soon-to-expire/expired certificates and deprecated TLS
protocol versions. This is a passive connection handshake — fully
non-destructive.

The stdlib ``ssl``/``socket`` calls are blocking, so the work runs in a thread
via :func:`asyncio.to_thread` to keep the scan cooperative.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity

_DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
_EXPIRY_WARN_DAYS = 21


@dataclass
class _TlsInfo:
    protocol: str | None
    not_after: dt.datetime | None
    error: str | None = None


class TlsCheck(Check):
    id = "tls"
    name = "TLS/SSL configuration"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        parts = urlparse(ctx.target.base_url)
        if parts.scheme != "https":
            return [
                Finding(
                    check_id=self.id,
                    title="Site is not served over HTTPS",
                    severity=Severity.HIGH,
                    description=(
                        "The target base URL uses plaintext HTTP, exposing all "
                        "traffic (including login cookies) to interception."
                    ),
                    remediation=(
                        "Serve the site over HTTPS with a valid certificate and "
                        "redirect HTTP to HTTPS."
                    ),
                    url=ctx.target.base_url,
                    evidence="scheme=http",
                )
            ]

        host = parts.hostname or ""
        port = parts.port or 443
        info = await asyncio.to_thread(
            self._probe, host, port, ctx.profile.timeout_seconds
        )

        if info.error is not None:
            return [
                Finding(
                    check_id=self.id,
                    title="TLS handshake failed",
                    severity=Severity.INFO,
                    description=f"Could not complete a TLS handshake: {info.error}.",
                    remediation="Verify the certificate chain and TLS configuration.",
                    url=ctx.target.base_url,
                    evidence=info.error,
                )
            ]

        findings: list[Finding] = []

        if info.protocol in _DEPRECATED_PROTOCOLS:
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Deprecated TLS protocol negotiated ({info.protocol})",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The server negotiated {info.protocol}, which is "
                        "deprecated and vulnerable to known downgrade/crypto "
                        "attacks."
                    ),
                    remediation="Disable TLS 1.1 and below; require TLS 1.2+.",
                    url=ctx.target.base_url,
                    evidence=f"protocol={info.protocol}",
                )
            )

        if info.not_after is not None:
            days_left = (info.not_after - _utcnow()).days
            if days_left < 0:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="TLS certificate has expired",
                        severity=Severity.HIGH,
                        description=(
                            f"The certificate expired on "
                            f"{info.not_after.date().isoformat()}."
                        ),
                        remediation="Renew the certificate immediately (e.g. Let's Encrypt auto-renewal).",
                        url=ctx.target.base_url,
                        evidence=f"not_after={info.not_after.date().isoformat()}",
                    )
                )
            elif days_left <= _EXPIRY_WARN_DAYS:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"TLS certificate expires soon ({days_left} days)",
                        severity=Severity.LOW,
                        description=(
                            "The certificate is close to expiry; an expired "
                            "certificate breaks HTTPS for all visitors."
                        ),
                        remediation="Ensure automated renewal is configured and working.",
                        url=ctx.target.base_url,
                        evidence=f"not_after={info.not_after.date().isoformat()}",
                    )
                )

        return findings

    @staticmethod
    def _probe(host: str, port: int, timeout: float) -> _TlsInfo:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    protocol = ssock.version()
                    cert = ssock.getpeercert()
        except (ssl.SSLError, socket.error, OSError) as exc:
            return _TlsInfo(protocol=None, not_after=None, error=str(exc))

        not_after = None
        raw = cert.get("notAfter") if cert else None
        if raw:
            try:
                not_after = dt.datetime.strptime(
                    raw, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=dt.timezone.utc)
            except ValueError:
                not_after = None
        return _TlsInfo(protocol=protocol, not_after=not_after)


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


register(TlsCheck())
