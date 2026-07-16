"""Scan orchestration: run applicable checks concurrently and collect results."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Iterable

import httpx

from .finding import Finding, Severity
from .http import RateLimitedClient
from .profile import Profile
from .target import Target
from ..checks.base import Check, CheckContext, all_checks


@dataclass
class ScanResult:
    """The outcome of a scan."""

    target: Target
    profile_name: str
    findings: list[Finding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.completed_at - self.started_at)

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered most-severe first, then by check id."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.check_id, f.title),
        )

    def severity_counts(self) -> dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def hardening_score(self) -> int:
        """A 0–100 posture score (higher is better).

        Starts at 100 and deducts weighted penalties per finding by severity,
        clamped to the 0–100 range. INFO findings do not affect the score. This
        is a heuristic posture indicator for trend tracking, not a CVSS
        aggregate.
        """
        penalties = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        deduction = sum(penalties[f.severity] for f in self.findings)
        return max(0, min(100, 100 - deduction))

    def grade(self) -> str:
        """Letter grade derived from :meth:`hardening_score`."""
        score = self.hardening_score()
        for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (50, "D")):
            if score >= threshold:
                return letter
        return "F"


class Scanner:
    """Runs a set of checks against a target under a given profile."""

    def __init__(self, checks: Iterable[Check] | None = None) -> None:
        self._checks = list(checks) if checks is not None else all_checks()

    async def scan(
        self,
        target: Target,
        profile: Profile,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> ScanResult:
        """Run all applicable checks. Enforces the authorization gate first."""
        target.require_authorization()

        result = ScanResult(target=target, profile_name=profile.name)
        loop = asyncio.get_running_loop()
        result.started_at = loop.time()
        wall_start = time.time()

        applicable = [c for c in self._checks if c.applies(profile)]

        async with RateLimitedClient(profile, transport=transport) as client:
            ctx = CheckContext(target=target, client=client, profile=profile)
            outcomes = await asyncio.gather(
                *(self._run_one(check, ctx) for check in applicable),
                return_exceptions=True,
            )

        for check, outcome in zip(applicable, outcomes):
            result.checks_run.append(check.id)
            if isinstance(outcome, Exception):
                result.errors.append(f"{check.id}: {outcome!r}")
            else:
                result.findings.extend(outcome)

        result.completed_at = loop.time()
        # Prefer wall-clock for human-facing duration; loop clock for ordering.
        result.started_at = 0.0
        result.completed_at = time.time() - wall_start
        return result

    @staticmethod
    async def _run_one(check: Check, ctx: CheckContext) -> list[Finding]:
        return await check.run(ctx)
