"""Miscellaneous non-destructive endpoint checks.

Bundles a few small, related probes:

* REST API index exposure (``/wp-json/``)
* Externally triggerable ``wp-cron.php`` (DoS amplification vector)
* Absent ``/.well-known/security.txt`` (a disclosure best practice)

All are GET-only and non-destructive.
"""

from __future__ import annotations

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity


class RestApiIndexCheck(Check):
    id = "rest-api-index"
    name = "REST API index exposure"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        resp = await ctx.client.get(ctx.target.url_for("wp-json/"))
        if resp is None or resp.status_code != 200 or '"routes"' not in resp.text:
            return []
        return [
            Finding(
                check_id=self.id,
                title="REST API index is publicly reachable",
                severity=Severity.INFO,
                description=(
                    "The /wp-json/ index enumerates the site's REST routes and "
                    "active plugins that register endpoints, aiding reconnaissance."
                ),
                remediation=(
                    "This is default behavior; restrict or authenticate any "
                    "sensitive custom routes and keep plugins updated."
                ),
                url=resp.url,
                evidence="HTTP 200 with routes index",
            )
        ]


class WpCronCheck(Check):
    id = "wp-cron"
    name = "Externally triggerable wp-cron"
    requires_active_probes = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        resp = await ctx.client.get(ctx.target.url_for("wp-cron.php"))
        if resp is None or resp.status_code not in (200, 204):
            return []
        return [
            Finding(
                check_id=self.id,
                title="wp-cron.php is externally accessible",
                severity=Severity.LOW,
                description=(
                    "wp-cron.php can be triggered by anyone. Repeated external "
                    "requests can be used to exhaust resources (DoS amplification)."
                ),
                remediation=(
                    "Set define('DISABLE_WP_CRON', true); and run WP-Cron from a "
                    "real system cron job, and/or restrict access to wp-cron.php."
                ),
                url=resp.url,
                evidence=f"HTTP {resp.status_code} at wp-cron.php",
            )
        ]


class SecurityTxtCheck(Check):
    id = "security-txt"
    name = "security.txt presence"
    requires_active_probes = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        for path in (".well-known/security.txt", "security.txt"):
            resp = await ctx.client.get(ctx.target.url_for(path))
            if resp is not None and resp.status_code == 200 and "Contact" in resp.text:
                return []  # present — no finding
        return [
            Finding(
                check_id=self.id,
                title="No security.txt disclosure policy published",
                severity=Severity.INFO,
                description=(
                    "No /.well-known/security.txt was found. Publishing one gives "
                    "researchers a clear channel to report vulnerabilities (RFC 9116)."
                ),
                remediation=(
                    "Publish /.well-known/security.txt with at least a Contact "
                    "field and an Expires date."
                ),
                url=ctx.target.url_for(".well-known/security.txt"),
                evidence="security.txt not found",
                references=["https://www.rfc-editor.org/rfc/rfc9116"],
            )
        ]


register(RestApiIndexCheck())
register(WpCronCheck())
register(SecurityTxtCheck())
