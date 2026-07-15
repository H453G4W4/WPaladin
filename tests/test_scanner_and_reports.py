"""Integration tests: full scan orchestration and report rendering."""

from __future__ import annotations

import json

import pytest

from wp_sentinel.core.profile import STANDARD
from wp_sentinel.core.scanner import Scanner
from wp_sentinel.core.target import AuthorizationError, Target
from wp_sentinel.report import render
from wp_sentinel.checks import all_checks


def _vulnerable_site(mock_site):
    site = mock_site()
    site.add("/", text='<meta name="generator" content="WordPress 6.4.2"> '
                       '/wp-content/ /wp-includes/')
    site.add("/readme.html", text="WordPress Version 6.4.2")
    site.add("/xmlrpc.php", status=405,
             text="XML-RPC server accepts POST requests only.")
    site.add("/wp-json/wp/v2/users", text='[{"id":1,"slug":"admin"}]')
    site.add("/?author=1", status=302,
             headers={"Location": "https://example.com/author/admin/"})
    site.add("/.env", text="DB_PASSWORD=secret")
    site.add("/wp-content/uploads/", text="<title>Index of /wp-content/uploads</title>")
    return site


async def test_scan_requires_authorization(mock_site):
    site = mock_site()
    site.add("/", text="<html></html>")
    scanner = Scanner()
    target = Target.parse("https://example.com", authorized=False)
    with pytest.raises(AuthorizationError):
        await scanner.scan(target, STANDARD, transport=site.transport)


async def test_full_scan_finds_issues(mock_site):
    site = _vulnerable_site(mock_site)
    scanner = Scanner()
    target = Target.parse("https://example.com", authorized=True)
    result = await scanner.scan(target, STANDARD, transport=site.transport)

    check_ids = {f.check_id for f in result.findings}
    assert "wp-version" in check_ids
    assert "xmlrpc" in check_ids
    assert "user-enumeration" in check_ids
    assert "sensitive-files" in check_ids
    assert "security-headers" in check_ids

    assert result.highest_severity.value == "critical"  # .env exposure
    assert len(result.checks_run) == len(all_checks())
    assert not result.errors

    # sorted_findings must be most-severe-first
    ranks = [f.severity.rank for f in result.sorted_findings()]
    assert ranks == sorted(ranks, reverse=True)


async def test_reports_render(mock_site):
    site = _vulnerable_site(mock_site)
    scanner = Scanner()
    target = Target.parse("https://example.com", authorized=True)
    result = await scanner.scan(target, STANDARD, transport=site.transport)

    js = render("json", result)
    payload = json.loads(js)
    assert payload["tool"] == "wp-sentinel"
    assert payload["target"] == "https://example.com"
    assert payload["highest_severity"] == "critical"
    assert len(payload["findings"]) == len(result.findings)

    html = render("html", result)
    assert "<!DOCTYPE html>" in html
    assert "example.com" in html
    assert "CRITICAL" in html

    csv_out = render("csv", result)
    assert "check_id,severity,score" in csv_out.splitlines()[0]
    assert "critical" in csv_out


def test_render_unknown_format_raises():
    with pytest.raises(KeyError):
        render("pdf", None)


async def test_scan_survives_check_error(mock_site, monkeypatch):
    """A check that raises must not abort the whole scan."""
    from wp_sentinel.checks.base import Check

    class Boom(Check):
        id = "boom"
        name = "always fails"

        async def run(self, ctx):
            raise RuntimeError("kaboom")

    site = mock_site()
    site.add("/", text="<html>/wp-content/</html>")
    scanner = Scanner(checks=[Boom()])
    target = Target.parse("https://example.com", authorized=True)
    result = await scanner.scan(target, STANDARD, transport=site.transport)
    assert result.findings == []
    assert any("boom" in e for e in result.errors)
