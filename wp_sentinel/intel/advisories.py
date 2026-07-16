"""Vulnerability-intelligence engine.

Correlates enumerated component versions (WordPress core, plugins, themes)
against a dataset of known advisories using an affected-range model
(``introduced`` inclusive lower bound, ``fixed`` exclusive upper bound), the
same shape used by OSV and GitHub Security Advisories.

This is *intelligence*, not exploitation: it tells an operator which of their
installed versions have publicly known vulnerabilities and what to upgrade to.
It never attempts to trigger any vulnerability.

The bundled dataset (``data/advisories.json``) is a small seed for demonstration
and testing. Point it at a live feed (WPScan, NVD, wpvulndb export) for
production coverage — see the docs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_DATA_FILE = Path(__file__).parent / "data" / "advisories.json"


def parse_version(raw: str) -> tuple[int, ...]:
    """Parse a dotted version into a comparable integer tuple.

    Trailing non-numeric segments (e.g. ``-beta``) are ignored; a leading ``v``
    is stripped. Returns an empty tuple for unparseable input.
    """
    cleaned = raw.strip().lstrip("vV")
    parts: list[int] = []
    for segment in cleaned.split("."):
        num = ""
        for ch in segment:
            if ch.isdigit():
                num += ch
            else:
                break
        if num == "":
            break
        parts.append(int(num))
    return tuple(parts)


def version_lt(a: str, b: str) -> bool:
    """Return True if version ``a`` < version ``b`` (zero-padded compare)."""
    ta, tb = parse_version(a), parse_version(b)
    length = max(len(ta), len(tb))
    ta += (0,) * (length - len(ta))
    tb += (0,) * (length - len(tb))
    return ta < tb


def version_ge(a: str, b: str) -> bool:
    """Return True if version ``a`` >= version ``b``."""
    return not version_lt(a, b)


@dataclass(frozen=True)
class Advisory:
    """A single known vulnerability affecting a component version range.

    Attributes:
        id: Stable internal identifier.
        component_type: "core", "plugin", or "theme".
        slug: Component slug ("wordpress" for core; e.g. "contact-form-7").
        title: Human-readable summary.
        severity: One of info/low/medium/high/critical.
        cvss: CVSS base score, if known.
        cve: CVE identifier, if assigned.
        introduced: Inclusive lower bound of the affected range (None = from 0).
        fixed: Exclusive upper bound / first patched version (None = unpatched).
        reference: Advisory URL.
    """

    id: str
    component_type: str
    slug: str
    title: str
    severity: str
    cvss: float | None = None
    cve: str | None = None
    introduced: str | None = None
    fixed: str | None = None
    reference: str | None = None

    def affects(self, version: str) -> bool:
        """Whether ``version`` falls within this advisory's affected range."""
        if not parse_version(version):
            return False
        if self.introduced is not None and version_lt(version, self.introduced):
            return False
        if self.fixed is not None and version_ge(version, self.fixed):
            return False
        return True

    @classmethod
    def from_dict(cls, data: dict) -> "Advisory":
        return cls(
            id=data["id"],
            component_type=data["component_type"],
            slug=data["slug"].lower(),
            title=data["title"],
            severity=data.get("severity", "medium"),
            cvss=data.get("cvss"),
            cve=data.get("cve"),
            introduced=data.get("introduced"),
            fixed=data.get("fixed"),
            reference=data.get("reference"),
        )


class VulnerabilityDatabase:
    """An indexed collection of advisories queryable by component + version."""

    def __init__(self, advisories: list[Advisory]) -> None:
        self._advisories = list(advisories)
        self._index: dict[tuple[str, str], list[Advisory]] = {}
        for adv in self._advisories:
            self._index.setdefault((adv.component_type, adv.slug), []).append(adv)

    def __len__(self) -> int:
        return len(self._advisories)

    def matches(
        self, component_type: str, slug: str, version: str
    ) -> list[Advisory]:
        """Return advisories affecting ``slug`` at ``version`` for the given type."""
        candidates = self._index.get((component_type, slug.lower()), [])
        return [adv for adv in candidates if adv.affects(version)]

    @classmethod
    def from_json(cls, text: str) -> "VulnerabilityDatabase":
        payload = json.loads(text)
        advisories = payload.get("advisories", []) if isinstance(payload, dict) else payload
        return cls([Advisory.from_dict(item) for item in advisories])

    @classmethod
    def load(cls, path: str | Path) -> "VulnerabilityDatabase":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    @classmethod
    def default(cls) -> "VulnerabilityDatabase":
        """Load the bundled seed dataset (empty-safe if missing)."""
        if not _DATA_FILE.exists():
            return cls([])
        return cls.load(_DATA_FILE)
