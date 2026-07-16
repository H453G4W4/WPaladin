"""Enumerate WordPress plugins and disclose versions from public assets.

Plugin slugs are parsed from asset URLs on the homepage (a passive signal).
Under active-probe profiles, the check also reads each plugin's ``readme.txt``
(a public file shipped with plugins) to extract the "Stable tag" version, since
outdated plugins are the most common WordPress attack vector.

Non-destructive: only GET requests to public asset paths.
"""

from __future__ import annotations

import re

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity

_PLUGIN_REF = re.compile(r"/wp-content/plugins/([a-z0-9][a-z0-9_-]+)/", re.IGNORECASE)
_STABLE_TAG = re.compile(r"Stable tag:\s*([0-9][0-9A-Za-z.\-]*)", re.IGNORECASE)
_MAX_README_PROBES = 25


class PluginEnumerationCheck(Check):
    id = "plugins"
    name = "Plugin enumeration and version disclosure"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        home = await ctx.client.get(ctx.target.base_url)
        if home is None:
            return []

        slugs = sorted(set(m.group(1).lower() for m in _PLUGIN_REF.finditer(home.text)))
        if not slugs:
            return []

        findings: list[Finding] = [
            Finding(
                check_id=self.id,
                title=f"{len(slugs)} plugin(s) discoverable from public assets",
                severity=Severity.INFO,
                description=(
                    "Plugin slugs are exposed via asset URLs on the homepage: "
                    + ", ".join(slugs[:15])
                    + ("…" if len(slugs) > 15 else "")
                    + ". Attackers use these to match known plugin CVEs."
                ),
                remediation=(
                    "Keep all plugins updated and remove unused ones. Consider "
                    "asset URL obfuscation only as defense-in-depth, not a fix."
                ),
                url=ctx.target.base_url,
                evidence=f"slugs={','.join(slugs[:15])}",
            )
        ]

        if not ctx.profile.active_probes:
            return findings

        for slug in slugs[:_MAX_README_PROBES]:
            readme = await ctx.client.get(
                ctx.target.url_for(f"wp-content/plugins/{slug}/readme.txt")
            )
            if readme is None or readme.status_code != 200:
                continue
            match = _STABLE_TAG.search(readme.text)
            if not match:
                continue
            version = match.group(1)
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Plugin '{slug}' version disclosed ({version})",
                    severity=Severity.LOW,
                    description=(
                        f"The readme.txt for '{slug}' discloses version {version}, "
                        "letting attackers check it against public vulnerability "
                        "databases."
                    ),
                    remediation=(
                        f"Keep '{slug}' updated to the latest version and review "
                        "its advisories. Block readme.txt if not needed."
                    ),
                    url=readme.url,
                    evidence=f"{slug} Stable tag: {version}",
                )
            )

        return findings


register(PluginEnumerationCheck())
