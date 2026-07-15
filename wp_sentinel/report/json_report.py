"""JSON report renderer (machine-readable, SIEM-friendly)."""

from __future__ import annotations

import json

from .. import __version__


def render_json(result) -> str:
    """Render a :class:`ScanResult` as pretty-printed JSON."""
    payload = {
        "tool": "wp-sentinel",
        "version": __version__,
        "target": result.target.base_url,
        "profile": result.profile_name,
        "duration_seconds": round(result.duration_seconds, 3),
        "checks_run": result.checks_run,
        "severity_counts": result.severity_counts(),
        "highest_severity": (
            result.highest_severity.value if result.highest_severity else None
        ),
        "findings": [f.to_dict() for f in result.sorted_findings()],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2, sort_keys=False)
