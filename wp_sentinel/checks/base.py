"""Base class and registry for checks.

A *check* is a self-contained, non-destructive probe that inspects a target and
yields :class:`~wp_sentinel.core.finding.Finding` objects. Checks are registered
in a global ordered registry and run by the scanner.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from ..core.finding import Finding
from ..core.http import RateLimitedClient
from ..core.profile import Profile
from ..core.target import Target


@dataclass
class CheckContext:
    """Everything a check needs to do its work."""

    target: Target
    client: RateLimitedClient
    profile: Profile


class Check(abc.ABC):
    """Abstract base for all checks.

    Subclasses must define ``id`` and ``name`` and implement :meth:`run`. Set
    ``requires_active_probes = True`` for checks that make extra requests beyond
    inspecting core endpoints; those are skipped under the passive profile.
    """

    id: str = ""
    name: str = ""
    requires_active_probes: bool = False

    @abc.abstractmethod
    async def run(self, ctx: CheckContext) -> list[Finding]:
        """Execute the check and return any findings (possibly empty)."""
        raise NotImplementedError

    def applies(self, profile: Profile) -> bool:
        """Whether this check should run under the given profile."""
        if self.requires_active_probes and not profile.active_probes:
            return False
        return True


_REGISTRY: dict[str, Check] = {}


def register(check: Check) -> Check:
    """Register a check instance. Raises on duplicate or malformed ids."""
    if not check.id:
        raise ValueError(f"{type(check).__name__} must define a non-empty id.")
    if check.id in _REGISTRY:
        raise ValueError(f"Duplicate check id: {check.id!r}.")
    _REGISTRY[check.id] = check
    return check


def all_checks() -> list[Check]:
    """Return registered checks in registration order."""
    return list(_REGISTRY.values())


def clear_registry() -> None:
    """Testing helper: empty the registry."""
    _REGISTRY.clear()
