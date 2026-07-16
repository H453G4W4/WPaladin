"""Correlate detected component versions against known-vulnerability advisories.

This is the tool's *depth* layer: instead of only reporting that a version is
disclosed, it reports whether that specific version has publicly known
vulnerabilities, with CVE, CVSS, and the exact patched version to upgrade to.

It reuses the same passive signals the version/plugin checks already read (the
generator tag, ``readme.html``, and plugin ``readme.txt`` files) and performs no
active exploitation — it only looks up what is already public knowledge about
the versions it detects.
"""

from __future__ import annotations

from .base import Check, CheckContext, register
from .plugins import _PLUGIN_REF, _STABLE_TAG, _MAX_README_PROBES
from .wp_version import _META_GENERATOR, _README_VERSION
from ..core.finding import Finding, Severity
from ..intel import VulnerabilityDatabase

_SEVERITY = {s.value: s for s in Severity}


class KnownVulnerabilityCheck(Check):
    id = "known-vulns"
    name = "Known-vulnerability correlation"
    requires_active_probes = True

    def __init__(self, database: VulnerabilityDatabase | None = None) -> None:
        self._db = database if database is not None else VulnerabilityDatabase.default()

    async def run(self, ctx: CheckContext) -> list[Finding]:
        if len(self._db) == 0:
            return []

        findings: list[Finding] = []
        home = await ctx.client.get(ctx.target.base_url)
        if home is None:
            return []

        core_version = await self._core_version(ctx, home.text)
        if core_version:
            findings.extend(
                self._advisory_findings("core", "wordpress", core_version, ctx.target.base_url)
            )

        slugs = sorted({m.group(1).lower() for m in _PLUGIN_REF.finditer(home.text)})
        for slug in slugs[:_MAX_README_PROBES]:
            readme = await ctx.client.get(
                ctx.target.url_for(f"wp-content/plugins/{slug}/readme.txt")
            )
            if readme is None or readme.status_code != 200:
                continue
            match = _STABLE_TAG.search(readme.text)
            if not match:
                continue
            findings.extend(
                self._advisory_findings("plugin", slug, match.group(1), readme.url)
            )
        return findings

    async def _core_version(self, ctx: CheckContext, home_body: str) -> str | None:
        meta = _META_GENERATOR.search(home_body)
        if meta and meta.group(1):
            return meta.group(1)
        readme = await ctx.client.get(ctx.target.url_for("readme.html"))
        if readme is not None and readme.status_code == 200:
            rm = _README_VERSION.search(readme.text)
            if rm:
                return rm.group(1)
        return None

    def _advisory_findings(
        self, component_type: str, slug: str, version: str, url: str
    ) -> list[Finding]:
        findings = []
        label = "WordPress core" if component_type == "core" else f"plugin '{slug}'"
        for adv in self._db.matches(component_type, slug, version):
            severity = _SEVERITY.get(adv.severity, Severity.MEDIUM)
            fix = (
                f"Upgrade {label} to {adv.fixed} or later."
                if adv.fixed
                else f"No fixed version is recorded; mitigate or remove {label}."
            )
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Known vulnerability in {label} {version}: {adv.title}",
                    severity=severity,
                    description=(
                        f"The detected {label} version {version} is affected by a "
                        f"publicly known vulnerability"
                        + (f" ({adv.cve})" if adv.cve else "")
                        + f". Affected range: "
                        + (f">= {adv.introduced} " if adv.introduced else "")
                        + (f"< {adv.fixed}" if adv.fixed else "(no fix released)")
                        + "."
                    ),
                    remediation=fix,
                    url=url,
                    evidence=f"{slug} {version} matches advisory {adv.id}",
                    cve=adv.cve,
                    cvss=adv.cvss,
                    owasp="A06:2021",
                    cwe="CWE-1035",
                    references=[adv.reference] if adv.reference else [],
                )
            )
        return findings


register(KnownVulnerabilityCheck())
