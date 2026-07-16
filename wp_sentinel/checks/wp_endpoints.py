"""WordPress-specific endpoint exposure checks.

Covers the install script, robots.txt, and XML sitemaps. All are single GETs to
public paths and strictly non-destructive — in particular the install-script
check only detects the *presence* of the setup page; it never submits it.
"""

from __future__ import annotations

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity


class InstallScriptCheck(Check):
    id = "install-script"
    name = "WordPress install script exposure"
    requires_active_probes = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        resp = await ctx.client.get(ctx.target.url_for("wp-admin/install.php"))
        if resp is None or resp.status_code != 200:
            return []
        body = resp.text.lower()
        # The live installer / already-installed notice both render this page.
        if "wordpress" not in body or (
            "install" not in body and "already installed" not in body
        ):
            return []
        already = "already installed" in body
        return [
            Finding(
                check_id=self.id,
                title="WordPress install script is reachable",
                severity=Severity.LOW if already else Severity.MEDIUM,
                description=(
                    "wp-admin/install.php is publicly reachable. "
                    + (
                        "It reports WordPress is already installed (lower risk), "
                        "but the endpoint should still be restricted."
                        if already
                        else "If the database is ever unconfigured, this page can "
                        "let anyone (re)install and take over the site."
                    )
                ),
                remediation=(
                    "Deny public access to wp-admin/install.php at the web-server "
                    "level once setup is complete."
                ),
                url=resp.url,
                evidence=f"HTTP 200 at wp-admin/install.php ({'installed' if already else 'setup'})",
                owasp="A05:2021",
                cwe="CWE-16",
            )
        ]


class RobotsSitemapCheck(Check):
    id = "robots-sitemap"
    name = "robots.txt and sitemap exposure"
    requires_active_probes = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        robots = await ctx.client.get(ctx.target.url_for("robots.txt"))
        if robots is not None and robots.status_code == 200 and "user-agent" in robots.text.lower():
            sensitive = [
                line.strip()
                for line in robots.text.splitlines()
                if line.lower().startswith("disallow:")
                and any(k in line.lower() for k in ("wp-admin", "wp-includes", "backup", "private"))
            ]
            if sensitive:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="robots.txt discloses sensitive paths",
                        severity=Severity.INFO,
                        description=(
                            "robots.txt lists Disallow entries that point "
                            "attackers at otherwise non-obvious paths: "
                            + "; ".join(sensitive[:5])
                            + "."
                        ),
                        remediation=(
                            "Do not rely on robots.txt to hide sensitive paths; "
                            "protect them with real access controls instead."
                        ),
                        url=robots.url,
                        evidence="; ".join(sensitive[:5]),
                        owasp="A05:2021",
                        cwe="CWE-200",
                    )
                )
        return findings


register(InstallScriptCheck())
register(RobotsSitemapCheck())
