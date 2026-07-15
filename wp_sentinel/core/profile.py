"""Scan profiles control politeness, concurrency, and which checks run.

Profiles are intentionally conservative. Even the most thorough profile here is
non-destructive: it makes more requests, but never exploits or attacks.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    """A named set of scan parameters.

    Attributes:
        name: Profile identifier.
        concurrency: Max simultaneous in-flight requests.
        delay_seconds: Minimum delay between successive requests (politeness).
        timeout_seconds: Per-request timeout.
        active_probes: Whether to make extra (still non-destructive) requests
            such as checking for known sensitive file paths.
        description: Human-readable summary.
    """

    name: str
    concurrency: int
    delay_seconds: float
    timeout_seconds: float
    active_probes: bool
    description: str


PASSIVE = Profile(
    name="passive",
    concurrency=2,
    delay_seconds=0.5,
    timeout_seconds=10.0,
    active_probes=False,
    description="Minimal footprint: only inspects the homepage and a few core "
    "endpoints. Best for a first, low-noise look.",
)

STANDARD = Profile(
    name="standard",
    concurrency=4,
    delay_seconds=0.2,
    timeout_seconds=15.0,
    active_probes=True,
    description="Balanced default: all non-destructive checks, including probes "
    "for exposed sensitive files, at a polite request rate.",
)

THOROUGH = Profile(
    name="thorough",
    concurrency=8,
    delay_seconds=0.05,
    timeout_seconds=20.0,
    active_probes=True,
    description="Higher concurrency for authorized audits of your own "
    "infrastructure. Still fully non-destructive.",
)

PROFILES: dict[str, Profile] = {p.name: p for p in (PASSIVE, STANDARD, THOROUGH)}


def get_profile(name: str) -> Profile:
    """Look up a profile by name, raising ``KeyError`` with a helpful message."""
    try:
        return PROFILES[name]
    except KeyError:
        available = ", ".join(sorted(PROFILES))
        raise KeyError(f"Unknown profile {name!r}. Available: {available}.") from None
