"""Detect WordPress and disclose its version from public signals.

Version disclosure is not itself an exploit, but a precisely known core version
makes it trivial for an attacker to match public CVEs. This check reports the
version (INFO) and flags when it is exposed via the ``readme.html`` file or the
``<meta name="generator">`` tag (LOW), which are easy to suppress.
"""

from __future__ import annotations

import re

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity

_META_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)?',
    re.IGNORECASE,
)
_README_VERSION = re.compile(r"Version\s*([\d.]+)", re.IGNORECASE)
_WP_MARKERS = ("/wp-content/", "/wp-includes/", "wp-json")


class WordPressVersionCheck(Check):
    id = "wp-version"
    name = "WordPress detection and version disclosure"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        home = await ctx.client.get(ctx.target.base_url)
        if home is None:
            return findings

        body = home.text
        is_wordpress = any(marker in body for marker in _WP_MARKERS)

        meta_match = _META_GENERATOR.search(body)
        if meta_match:
            is_wordpress = True

        if not is_wordpress:
            return findings

        version = meta_match.group(1) if meta_match and meta_match.group(1) else None

        if meta_match and version:
            findings.append(
                Finding(
                    check_id=self.id,
                    title="WordPress version disclosed via generator meta tag",
                    severity=Severity.LOW,
                    description=(
                        f"The homepage exposes WordPress {version} through the "
                        "<meta name=\"generator\"> tag, helping attackers map "
                        "the core version to known vulnerabilities."
                    ),
                    remediation=(
                        "Remove the generator tag, e.g. add "
                        "remove_action('wp_head', 'wp_generator'); to your theme "
                        "or a small mu-plugin."
                    ),
                    url=ctx.target.base_url,
                    evidence=f"generator: WordPress {version}",
                )
            )

        # readme.html is shipped with core and leaks the version.
        readme = await ctx.client.get(ctx.target.url_for("readme.html"))
        if readme is not None and readme.status_code == 200:
            readme_match = _README_VERSION.search(readme.text)
            readme_version = readme_match.group(1) if readme_match else None
            version = version or readme_version
            findings.append(
                Finding(
                    check_id=self.id,
                    title="WordPress readme.html is publicly accessible",
                    severity=Severity.LOW,
                    description=(
                        "readme.html ships with WordPress core and discloses the "
                        "exact version"
                        + (f" ({readme_version})" if readme_version else "")
                        + ", aiding version fingerprinting."
                    ),
                    remediation=(
                        "Delete or deny access to readme.html (it is recreated on "
                        "core updates; block it at the web-server level)."
                    ),
                    url=readme.url,
                    evidence=f"readme.html version {readme_version}"
                    if readme_version
                    else "readme.html accessible",
                )
            )

        findings.append(
            Finding(
                check_id=self.id,
                title="WordPress detected"
                + (f" (version {version})" if version else " (version unknown)"),
                severity=Severity.INFO,
                description=(
                    "The target appears to run WordPress based on core paths "
                    "and/or the generator tag."
                    + (f" Detected version: {version}." if version else "")
                ),
                remediation=(
                    "Keep WordPress core, themes, and plugins updated. Version "
                    "disclosure alone is not a vulnerability but eases targeting."
                ),
                url=ctx.target.base_url,
                evidence=f"version={version}" if version else "core paths present",
            )
        )
        return findings


register(WordPressVersionCheck())
