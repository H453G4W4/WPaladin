"""Finding model, severity levels, and CVSS-style scoring.

A :class:`Finding` is the atomic result produced by a check. Severity maps to a
representative CVSS v3.1 base score so reports can present a consistent numeric
risk value, but each finding may also carry an explicit ``cvss`` override when a
known CVE score applies.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.Enum):
    """Ordered severity levels aligned to CVSS v3.1 qualitative ratings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (higher is more severe)."""
        return _SEVERITY_ORDER[self]

    @property
    def representative_cvss(self) -> float:
        """A representative CVSS v3.1 base score for this qualitative level."""
        return _SEVERITY_CVSS[self]

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Midpoints of the CVSS v3.1 qualitative severity bands.
_SEVERITY_CVSS: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 2.0,
    Severity.MEDIUM: 5.5,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 9.5,
}


@dataclass
class Finding:
    """A single security observation produced by a check.

    Attributes:
        check_id: Stable identifier of the check that produced this finding.
        title: Short human-readable title.
        severity: Qualitative severity level.
        description: What was observed and why it matters.
        remediation: Concrete guidance to resolve the issue.
        url: The specific URL/evidence location, if applicable.
        evidence: Short excerpt or value supporting the finding (never full
            response bodies or secrets).
        cve: Associated CVE identifier, if any.
        cvss: Explicit CVSS base score override; falls back to the severity's
            representative score when ``None``.
        references: Helpful links (advisories, docs).
    """

    check_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    url: str | None = None
    evidence: str | None = None
    cve: str | None = None
    cvss: float | None = None
    references: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Effective CVSS score: explicit override or severity representative."""
        return self.cvss if self.cvss is not None else self.severity.representative_cvss

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["score"] = self.score
        return data
