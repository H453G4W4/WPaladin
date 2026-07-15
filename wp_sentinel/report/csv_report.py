"""CSV report renderer (spreadsheet / SIEM import)."""

from __future__ import annotations

import csv
import io


def render_csv(result) -> str:
    """Render a :class:`ScanResult` as CSV, one row per finding."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "check_id",
            "severity",
            "score",
            "title",
            "url",
            "cve",
            "evidence",
            "remediation",
        ]
    )
    for finding in result.sorted_findings():
        writer.writerow(
            [
                finding.check_id,
                finding.severity.value,
                f"{finding.score:.1f}",
                finding.title,
                finding.url or "",
                finding.cve or "",
                finding.evidence or "",
                finding.remediation,
            ]
        )
    return buffer.getvalue()
