"""Check for missing HTTP security headers on the homepage.

Missing hardening headers do not directly compromise a site but weaken defenses
against clickjacking, MIME sniffing, protocol downgrade, and XSS. Each missing
header is reported individually with tailored remediation.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity


@dataclass(frozen=True)
class _HeaderSpec:
    header: str
    severity: Severity
    title: str
    description: str
    remediation: str


_HEADERS: tuple[_HeaderSpec, ...] = (
    _HeaderSpec(
        "Strict-Transport-Security",
        Severity.MEDIUM,
        "Missing HSTS header",
        "Without HSTS, browsers may connect over plaintext HTTP, exposing users "
        "to downgrade and cookie-hijacking attacks.",
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "over HTTPS.",
    ),
    _HeaderSpec(
        "Content-Security-Policy",
        Severity.MEDIUM,
        "Missing Content-Security-Policy header",
        "A CSP is the strongest defense-in-depth control against cross-site "
        "scripting; its absence leaves XSS payloads unconstrained.",
        "Define a CSP starting from a restrictive default-src policy and relax "
        "as needed for your theme/plugins.",
    ),
    _HeaderSpec(
        "X-Frame-Options",
        Severity.LOW,
        "Missing X-Frame-Options / frame-ancestors",
        "Without frame protection the site can be embedded in an attacker frame "
        "for clickjacking.",
        "Send 'X-Frame-Options: SAMEORIGIN' or a CSP 'frame-ancestors' directive.",
    ),
    _HeaderSpec(
        "X-Content-Type-Options",
        Severity.LOW,
        "Missing X-Content-Type-Options header",
        "Browsers may MIME-sniff responses, enabling some content-type "
        "confusion attacks.",
        "Send 'X-Content-Type-Options: nosniff'.",
    ),
    _HeaderSpec(
        "Referrer-Policy",
        Severity.INFO,
        "Missing Referrer-Policy header",
        "Full referrer URLs may leak to third parties.",
        "Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
)


class SecurityHeadersCheck(Check):
    id = "security-headers"
    name = "HTTP security headers"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        resp = await ctx.client.get(ctx.target.base_url)
        if resp is None:
            return []

        findings: list[Finding] = []
        for spec in _HEADERS:
            if resp.header(spec.header) is None:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=spec.title,
                        severity=spec.severity,
                        description=spec.description,
                        remediation=spec.remediation,
                        url=resp.url,
                        evidence=f"{spec.header} header absent",
                    )
                )
        return findings


register(SecurityHeadersCheck())
