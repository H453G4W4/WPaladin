"""SARIF 2.1.0 report renderer.

SARIF (Static Analysis Results Interchange Format) lets WP-Sentinel findings be
ingested by GitHub code scanning, Azure DevOps, and other SARIF-aware tools.
Each distinct check becomes a ``rule``; each finding becomes a ``result``.
"""

from __future__ import annotations

import json

from .. import __version__
from ..core.finding import Finding, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _rule(finding: Finding) -> dict:
    rule: dict = {
        "id": finding.check_id,
        "name": finding.check_id.replace("-", "_"),
        "shortDescription": {"text": finding.title},
        "properties": {"security-severity": f"{finding.score:.1f}"},
    }
    tags = ["security"]
    if finding.owasp:
        tags.append(finding.owasp)
    if finding.cwe:
        rule["properties"]["cwe"] = finding.cwe
        tags.append(finding.cwe)
    rule["properties"]["tags"] = tags
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def render_sarif(result) -> str:
    """Render a :class:`ScanResult` as a SARIF 2.1.0 document."""
    findings = result.sorted_findings()

    # De-duplicate rules by check id, keeping the first (most severe) occurrence.
    rules: dict[str, dict] = {}
    for finding in findings:
        rules.setdefault(finding.check_id, _rule(finding))

    results = []
    for finding in findings:
        entry: dict = {
            "ruleId": finding.check_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": f"{finding.title}. {finding.description}"},
            "properties": {
                "severity": finding.severity.value,
                "cvss": finding.score,
                "remediation": finding.remediation,
            },
        }
        if finding.owasp:
            entry["properties"]["owasp"] = finding.owasp
        if finding.url:
            entry["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": finding.url}}}
            ]
        results.append(entry)

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "WP-Sentinel",
                        "version": __version__,
                        "informationUri": "https://github.com/h453g4w4/wpaladin",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "target": result.target.base_url,
                    "profile": result.profile_name,
                    "hardeningScore": result.hardening_score(),
                },
            }
        ],
    }
    return json.dumps(doc, indent=2)
