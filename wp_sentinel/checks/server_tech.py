"""Server, framework, and CDN/host detection from ordinary response headers.

Purely passive: reads only headers the server volunteers on a normal request
(``Server``, ``X-Powered-By``, and well-known CDN/host markers). No active
fingerprinting, banner grabbing, or version probing beyond this. Results are
INFO — useful context, not vulnerabilities — except ``X-Powered-By`` version
disclosure, which is a LOW information-leak.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity


@dataclass(frozen=True)
class _Marker:
    header: str
    provider: str
    # Substring to match in the header value (case-insensitive); None = any value.
    contains: str | None = None


# CDN / hosting indicators exposed via standard HTTP headers.
_MARKERS: tuple[_Marker, ...] = (
    _Marker("Server", "Cloudflare", "cloudflare"),
    _Marker("CF-Ray", "Cloudflare"),
    _Marker("Server", "LiteSpeed", "litespeed"),
    _Marker("X-LiteSpeed-Cache", "LiteSpeed"),
    _Marker("Server", "nginx", "nginx"),
    _Marker("Server", "Apache", "apache"),
    _Marker("Server", "Microsoft-IIS", "iis"),
    _Marker("X-Vercel-Id", "Vercel"),
    _Marker("X-Nf-Request-Id", "Netlify"),
    _Marker("Server", "AmazonS3", "amazons3"),
    _Marker("X-Amz-Cf-Id", "AWS CloudFront"),
    _Marker("X-Amz-Request-Id", "AWS"),
    _Marker("Server", "Hostinger", "hostinger"),
    _Marker("X-Hosting-Provider", "Hostinger", "hostinger"),
)


class ServerTechCheck(Check):
    id = "server-tech"
    name = "Server / CDN / hosting detection"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        resp = await ctx.client.get(ctx.target.base_url)
        if resp is None:
            return []

        findings: list[Finding] = []
        detected: list[str] = []
        for marker in _MARKERS:
            value = resp.header(marker.header)
            if value is None:
                continue
            if marker.contains and marker.contains not in value.lower():
                continue
            if marker.provider not in detected:
                detected.append(marker.provider)

        if detected:
            findings.append(
                Finding(
                    check_id=self.id,
                    title="Server / CDN / hosting technology disclosed",
                    severity=Severity.INFO,
                    description=(
                        "Response headers reveal infrastructure: "
                        + ", ".join(detected)
                        + ". This is normal but useful reconnaissance context."
                    ),
                    remediation=(
                        "Minimize verbose Server/X-Powered-By banners where your "
                        "stack allows; treat this as informational."
                    ),
                    url=resp.url,
                    evidence="detected: " + ", ".join(detected),
                    owasp="A05:2021",
                    cwe="CWE-200",
                )
            )

        powered_by = resp.header("X-Powered-By")
        if powered_by:
            findings.append(
                Finding(
                    check_id=self.id,
                    title="X-Powered-By discloses stack version",
                    severity=Severity.LOW,
                    description=(
                        f"The X-Powered-By header exposes '{powered_by}', "
                        "advertising the runtime and version to attackers."
                    ),
                    remediation=(
                        "Suppress X-Powered-By (PHP: expose_php=Off; or strip it "
                        "at the web server / CDN)."
                    ),
                    url=resp.url,
                    evidence=f"X-Powered-By: {powered_by}",
                    owasp="A05:2021",
                    cwe="CWE-200",
                )
            )
        return findings


register(ServerTechCheck())
