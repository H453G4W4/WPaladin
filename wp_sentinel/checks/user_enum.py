"""Detect username enumeration via the REST API and author archives.

Leaked usernames are the first half of a credential-stuffing or brute-force
attack. This check reads only public listing endpoints; it makes no login
attempts. It reports *that* usernames are enumerable, and includes a small
sample count as evidence — never a full user dump.
"""

from __future__ import annotations

import json

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity


class UserEnumerationCheck(Check):
    id = "user-enumeration"
    name = "Username enumeration"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []

        rest = await ctx.client.get(ctx.target.url_for("wp-json/wp/v2/users"))
        if rest is not None and rest.status_code == 200:
            count = self._count_users(rest.text)
            if count:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="Usernames enumerable via REST API",
                        severity=Severity.MEDIUM,
                        description=(
                            "The /wp-json/wp/v2/users endpoint returns public "
                            f"user data ({count} account(s) visible), exposing "
                            "login slugs for brute-force/credential-stuffing."
                        ),
                        remediation=(
                            "Restrict the users REST endpoint (e.g. via a "
                            "security plugin or a rest_endpoints filter) and "
                            "ensure display names differ from login names."
                        ),
                        url=rest.url,
                        evidence=f"{count} user(s) exposed via REST",
                    )
                )

        # Author archive redirect: /?author=1 -> /author/<login>/
        author = await ctx.client.get(ctx.target.url_for("?author=1"))
        if author is not None and author.status_code in (301, 302):
            location = author.header("Location") or ""
            if "/author/" in location:
                slug = location.rstrip("/").rsplit("/", 1)[-1]
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="Usernames enumerable via author archives",
                        severity=Severity.LOW,
                        description=(
                            "Requesting /?author=1 redirects to an author "
                            "archive that reveals a login slug."
                        ),
                        remediation=(
                            "Disable author archives if unused, or map author "
                            "slugs to values that differ from login names."
                        ),
                        url=author.url,
                        evidence=f"redirect reveals author slug '{slug}'",
                    )
                )

        return findings

    @staticmethod
    def _count_users(body: str) -> int:
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return 0
        if isinstance(data, list):
            return len(data)
        return 0


register(UserEnumerationCheck())
