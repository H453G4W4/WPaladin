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
    _HeaderSpec(
        "Permissions-Policy",
        Severity.INFO,
        "Missing Permissions-Policy header",
        "Powerful browser features (camera, geolocation, etc.) are not "
        "restricted, widening the impact of an injected script.",
        "Send a Permissions-Policy that disables features you do not use, e.g. "
        "'geolocation=(), camera=(), microphone=()'.",
    ),
    _HeaderSpec(
        "Cross-Origin-Opener-Policy",
        Severity.LOW,
        "Missing Cross-Origin-Opener-Policy header",
        "Without COOP the page shares a browsing-context group with cross-origin "
        "openers, enabling some cross-window attacks (XS-Leaks).",
        "Send 'Cross-Origin-Opener-Policy: same-origin'.",
    ),
    _HeaderSpec(
        "Cross-Origin-Embedder-Policy",
        Severity.INFO,
        "Missing Cross-Origin-Embedder-Policy header",
        "COEP is required alongside COOP to enable cross-origin isolation.",
        "Send 'Cross-Origin-Embedder-Policy: require-corp' if you need isolation.",
    ),
    _HeaderSpec(
        "Cross-Origin-Resource-Policy",
        Severity.INFO,
        "Missing Cross-Origin-Resource-Policy header",
        "CORP lets a resource declare who may embed it, mitigating side-channel "
        "leaks.",
        "Send 'Cross-Origin-Resource-Policy: same-origin' where appropriate.",
    ),
)

# OWASP A05:2021 Security Misconfiguration; CWE-693 Protection Mechanism Failure.
_HEADER_OWASP = "A05:2021"
_HEADER_CWE = "CWE-693"

# Tokens that materially weaken a Content-Security-Policy.
_WEAK_CSP_TOKENS = ("unsafe-inline", "unsafe-eval")


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
                        owasp=_HEADER_OWASP,
                        cwe=_HEADER_CWE,
                    )
                )

        findings.extend(self._analyze_csp(resp))
        findings.extend(self._analyze_hsts(resp))
        return findings

    def _analyze_csp(self, resp) -> list[Finding]:
        csp = resp.header("Content-Security-Policy")
        if not csp:
            return []
        weak = [t for t in _WEAK_CSP_TOKENS if t in csp.lower()]
        if not weak:
            return []
        return [
            Finding(
                check_id=self.id,
                title="Content-Security-Policy weakened by unsafe directives",
                severity=Severity.LOW,
                description=(
                    "The CSP is present but includes "
                    + ", ".join(f"'{w}'" for w in weak)
                    + ", which substantially reduces its XSS protection."
                ),
                remediation=(
                    "Remove 'unsafe-inline'/'unsafe-eval'; adopt nonces or hashes "
                    "for inline scripts and styles."
                ),
                url=resp.url,
                evidence=f"CSP contains {', '.join(weak)}",
                owasp="A03:2021",
                cwe="CWE-79",
            )
        ]

    def _analyze_hsts(self, resp) -> list[Finding]:
        hsts = resp.header("Strict-Transport-Security")
        if not hsts:
            return []  # absence already reported by the missing-header loop
        lowered = hsts.lower()
        issues = []
        if "includesubdomains" not in lowered:
            issues.append("includeSubDomains")
        if "preload" not in lowered:
            issues.append("preload")
        if not issues:
            return []
        return [
            Finding(
                check_id=self.id,
                title="HSTS not ready for preload",
                severity=Severity.INFO,
                description=(
                    "HSTS is set but missing "
                    + " and ".join(issues)
                    + ", so it is not eligible for the browser preload list."
                ),
                remediation=(
                    "Use 'Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload' and submit to hstspreload.org."
                ),
                url=resp.url,
                evidence=f"HSTS: {hsts}",
                owasp=_HEADER_OWASP,
                cwe=_HEADER_CWE,
            )
        ]


register(SecurityHeadersCheck())
