"""Detect enabled directory listing on common WordPress directories.

An open directory index (Apache "Index of /" or nginx autoindex) exposes the
full file inventory of uploads and plugin directories, aiding reconnaissance.
This check only reads the index pages; it is non-destructive.
"""

from __future__ import annotations

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity

_DIRS = (
    "wp-content/uploads/",
    "wp-content/plugins/",
    "wp-includes/",
)
_MARKERS = ("Index of /", "<title>Index of", "autoindex")


class DirectoryListingCheck(Check):
    id = "directory-listing"
    name = "Directory listing enabled"
    requires_active_probes = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for directory in _DIRS:
            resp = await ctx.client.get(ctx.target.url_for(directory))
            if resp is None or resp.status_code != 200:
                continue
            if not any(marker in resp.text for marker in _MARKERS):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Directory listing enabled at /{directory}",
                    severity=Severity.LOW,
                    description=(
                        f"The /{directory} directory returns an autoindex, "
                        "exposing its full file inventory for reconnaissance."
                    ),
                    remediation=(
                        "Disable automatic directory indexes (Apache: "
                        "'Options -Indexes'; nginx: 'autoindex off;') and add an "
                        "empty index.php where appropriate."
                    ),
                    url=resp.url,
                    evidence=f"autoindex page served at /{directory}",
                )
            )
        return findings


register(DirectoryListingCheck())
