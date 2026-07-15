"""Tests for core models: findings, severity, target parsing, auth gate."""

from __future__ import annotations

import pytest

from wp_sentinel.core.finding import Finding, Severity
from wp_sentinel.core.target import AuthorizationError, Target


def test_severity_ordering_and_scores():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.CRITICAL.representative_cvss > Severity.LOW.representative_cvss
    assert Severity.INFO.representative_cvss == 0.0


def test_finding_score_defaults_to_severity():
    f = Finding("c", "t", Severity.HIGH, "d", "r")
    assert f.score == Severity.HIGH.representative_cvss


def test_finding_score_override():
    f = Finding("c", "t", Severity.HIGH, "d", "r", cvss=9.9)
    assert f.score == 9.9
    assert f.to_dict()["severity"] == "high"
    assert f.to_dict()["score"] == 9.9


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "https://example.com"),
        ("http://example.com/", "http://example.com"),
        ("https://Example.com/path?x=1", "https://example.com"),
        ("http://example.com:8080/foo", "http://example.com:8080"),
    ],
)
def test_target_parse_normalizes(raw, expected):
    assert Target.parse(raw).base_url == expected


def test_target_parse_rejects_bad_input():
    with pytest.raises(ValueError):
        Target.parse("")
    with pytest.raises(ValueError):
        Target.parse("ftp://example.com")


def test_target_url_for():
    t = Target.parse("https://example.com")
    assert t.url_for("readme.html") == "https://example.com/readme.html"
    assert t.url_for("/wp-json") == "https://example.com/wp-json"


def test_authorization_gate():
    t = Target.parse("https://example.com", authorized=False)
    with pytest.raises(AuthorizationError):
        t.require_authorization()
    Target.parse("https://example.com", authorized=True).require_authorization()
