"""Cookie security-attribute analysis.

Inspects ``Set-Cookie`` headers on the homepage for missing ``Secure``,
``HttpOnly``, and ``SameSite`` attributes. Read-only: the check never sends
credentials or attempts authentication — it only evaluates the attributes the
server sets on its own cookies.
"""

from __future__ import annotations

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity


def _cookie_name(raw: str) -> str:
    return raw.split("=", 1)[0].strip() or "(unnamed)"


class CookieSecurityCheck(Check):
    id = "cookies"
    name = "Cookie security attributes"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        resp = await ctx.client.get(ctx.target.base_url)
        if resp is None or not resp.set_cookies:
            return []

        https = ctx.target.base_url.startswith("https://")
        findings: list[Finding] = []
        for raw in resp.set_cookies:
            lowered = raw.lower()
            name = _cookie_name(raw)
            missing = []
            if https and "secure" not in lowered:
                missing.append("Secure")
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")
            if not missing:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Cookie '{name}' missing {', '.join(missing)}",
                    severity=Severity.LOW,
                    description=(
                        f"The cookie '{name}' is set without the "
                        f"{', '.join(missing)} attribute(s), weakening protection "
                        "against theft (missing Secure/HttpOnly) or CSRF "
                        "(missing SameSite)."
                    ),
                    remediation=(
                        "Set Secure and HttpOnly on session cookies and an "
                        "explicit SameSite policy (Lax or Strict)."
                    ),
                    url=resp.url,
                    evidence=f"{name}: missing {', '.join(missing)}",
                    owasp="A05:2021",
                    cwe="CWE-614",
                )
            )
        return findings


register(CookieSecurityCheck())
