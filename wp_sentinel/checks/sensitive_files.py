"""Probe for exposed sensitive files (config, VCS, backups, logs).

This is an *active* check (extra requests) but strictly non-destructive: it only
issues GET requests to a curated list of well-known sensitive paths and reports
which return a successful, non-HTML response indicating real exposure. It never
downloads full contents beyond a tiny confirmation snippet, and never modifies
anything.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity


@dataclass(frozen=True)
class _FileSpec:
    path: str
    severity: Severity
    title: str
    description: str
    # A marker that, if present in the body, confirms it is the real file and
    # not a themed 404 page returned with a 200 status.
    marker: str | None = None


_FILES: tuple[_FileSpec, ...] = (
    _FileSpec(
        ".env",
        Severity.CRITICAL,
        "Exposed .env file",
        "A .env file typically contains database credentials, API keys, and "
        "secrets. Public exposure is a critical breach.",
        marker="=",
    ),
    _FileSpec(
        ".git/config",
        Severity.HIGH,
        "Exposed .git repository",
        "A reachable .git directory lets attackers reconstruct source code and "
        "often recover committed secrets.",
        marker="[core]",
    ),
    _FileSpec(
        "wp-config.php.bak",
        Severity.CRITICAL,
        "Exposed wp-config backup",
        "A wp-config backup served as plaintext discloses database credentials "
        "and secret keys.",
        marker="DB_",
    ),
    _FileSpec(
        "wp-config.php~",
        Severity.CRITICAL,
        "Exposed wp-config editor backup",
        "Editor backup of wp-config.php served as plaintext discloses database "
        "credentials and secret keys.",
        marker="DB_",
    ),
    _FileSpec(
        "wp-content/debug.log",
        Severity.MEDIUM,
        "Exposed WordPress debug log",
        "debug.log can leak file paths, SQL errors, and other internals useful "
        "for further attacks.",
    ),
    _FileSpec(
        "wp-config.php.save",
        Severity.CRITICAL,
        "Exposed wp-config saved copy",
        "A saved copy of wp-config.php served as plaintext discloses database "
        "credentials and secret keys.",
        marker="DB_",
    ),
    _FileSpec(
        ".svn/entries",
        Severity.HIGH,
        "Exposed Subversion metadata",
        "A reachable .svn directory can disclose source code and repository "
        "structure.",
    ),
    _FileSpec(
        "composer.lock",
        Severity.LOW,
        "Exposed composer.lock",
        "composer.lock reveals exact PHP dependency versions, easing CVE matching.",
        marker="packages",
    ),
    _FileSpec(
        "package-lock.json",
        Severity.LOW,
        "Exposed package-lock.json",
        "package-lock.json reveals exact JS dependency versions, easing CVE "
        "matching.",
        marker="lockfileVersion",
    ),
    _FileSpec(
        "backup.zip",
        Severity.HIGH,
        "Exposed backup archive",
        "A downloadable site backup archive may contain source code, "
        "credentials, and database contents.",
    ),
    _FileSpec(
        "backup.sql",
        Severity.CRITICAL,
        "Exposed database dump (backup.sql)",
        "A publicly downloadable SQL dump exposes the entire database, including "
        "user records and hashes.",
        marker="INSERT INTO",
    ),
    _FileSpec(
        "database.sql",
        Severity.CRITICAL,
        "Exposed database dump (database.sql)",
        "A publicly downloadable SQL dump exposes the entire database, including "
        "user records and hashes.",
        marker="INSERT INTO",
    ),
    _FileSpec(
        "wp-config.php.swp",
        Severity.CRITICAL,
        "Exposed editor swap file for wp-config",
        "A Vim swap file for wp-config.php can be reconstructed to recover "
        "database credentials.",
    ),
    _FileSpec(
        ".DS_Store",
        Severity.LOW,
        "Exposed .DS_Store file",
        ".DS_Store leaks directory and file names that aid enumeration.",
    ),
)


class SensitiveFilesCheck(Check):
    id = "sensitive-files"
    name = "Exposed sensitive files"
    requires_active_probes = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for spec in _FILES:
            url = ctx.target.url_for(spec.path)
            resp = await ctx.client.get(url)
            if resp is None or resp.status_code != 200:
                continue
            # Guard against soft-404s that return 200 with an HTML page.
            body = resp.text
            if spec.marker is not None and spec.marker not in body:
                continue
            if spec.marker is None and self._looks_like_html(body):
                continue

            findings.append(
                Finding(
                    check_id=self.id,
                    title=spec.title,
                    severity=spec.severity,
                    description=spec.description,
                    remediation=(
                        f"Remove {spec.path} from the web root or deny access to "
                        "it at the web-server level, and rotate any credentials "
                        "that may have been exposed."
                    ),
                    url=resp.url,
                    evidence=f"HTTP 200 at {spec.path}",
                    owasp="A05:2021",
                    cwe="CWE-538",
                )
            )
        return findings

    @staticmethod
    def _looks_like_html(body: str) -> bool:
        head = body.lstrip()[:200].lower()
        return head.startswith("<!doctype html") or head.startswith("<html")


register(SensitiveFilesCheck())
