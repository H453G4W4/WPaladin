"""Tests for SARIF/Markdown reporters, hardening score, and finding metadata."""

from __future__ import annotations

import json

import pytest

from wp_sentinel.core.finding import Finding, Severity
from wp_sentinel.core.scanner import ScanResult
from wp_sentinel.core.target import Target
from wp_sentinel.report import render, MEDIA_TYPES


def _result(findings):
    r = ScanResult(target=Target.parse("https://example.com"), profile_name="standard")
    r.findings = findings
    r.checks_run = ["a", "b"]
    r.completed_at = 1.5
    return r


def _f(sev, **kw):
    return Finding("chk", f"{sev.value} issue", sev, "desc", "fix", **kw)


def test_hardening_score_and_grade():
    clean = _result([])
    assert clean.hardening_score() == 100 and clean.grade() == "A"

    r = _result([_f(Severity.CRITICAL), _f(Severity.MEDIUM)])
    assert r.hardening_score() == 100 - 40 - 8  # 52
    assert r.grade() == "D"

    floor = _result([_f(Severity.CRITICAL) for _ in range(5)])
    assert floor.hardening_score() == 0 and floor.grade() == "F"

    # INFO findings do not move the score.
    assert _result([_f(Severity.INFO), _f(Severity.INFO)]).hardening_score() == 100


def test_finding_metadata_roundtrip():
    f = _f(Severity.HIGH, owasp="A05:2021", cwe="CWE-200", cve="CVE-2024-0001")
    d = f.to_dict()
    assert d["owasp"] == "A05:2021" and d["cwe"] == "CWE-200"
    assert d["cve"] == "CVE-2024-0001"


def test_sarif_structure():
    r = _result([
        _f(Severity.CRITICAL, url="https://example.com/.env", owasp="A05:2021", cwe="CWE-538"),
        _f(Severity.LOW, owasp="A05:2021"),
    ])
    doc = json.loads(render("sarif", r))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "WP-Sentinel"
    # One rule per distinct check id.
    assert len(run["tool"]["driver"]["rules"]) == 1
    levels = {res["level"] for res in run["results"]}
    assert "error" in levels and "note" in levels
    assert run["properties"]["hardeningScore"] == r.hardening_score()
    # security-severity present for code-scanning severity mapping
    assert "security-severity" in run["tool"]["driver"]["rules"][0]["properties"]


def test_markdown_structure():
    r = _result([_f(Severity.CRITICAL, owasp="A05:2021", cwe="CWE-538",
                    url="https://example.com/.env", evidence="HTTP 200")])
    md = render("markdown", r)
    assert "# WP-Sentinel Security Report" in md
    assert "## Executive summary" in md
    assert "Hardening score" in md
    assert "OWASP:** A05:2021" in md
    assert "CWE:** CWE-538" in md
    # 'md' alias resolves to the same renderer
    assert render("md", r) == md


def test_media_types_cover_all_formats():
    for fmt in ("json", "html", "csv", "sarif", "markdown", "md"):
        assert fmt in MEDIA_TYPES


def test_unknown_format_lists_available():
    with pytest.raises(KeyError) as exc:
        render("pdf", _result([]))
    assert "sarif" in str(exc.value) and "markdown" in str(exc.value)
