"""Tests for individual checks using a mocked WordPress site."""

from __future__ import annotations

import pytest

from wp_sentinel.core.http import RateLimitedClient
from wp_sentinel.core.profile import STANDARD, PASSIVE
from wp_sentinel.core.target import Target
from wp_sentinel.checks.base import CheckContext
from wp_sentinel.checks.wp_version import WordPressVersionCheck
from wp_sentinel.checks.security_headers import SecurityHeadersCheck
from wp_sentinel.checks.xmlrpc import XmlRpcCheck
from wp_sentinel.checks.user_enum import UserEnumerationCheck
from wp_sentinel.checks.sensitive_files import SensitiveFilesCheck
from wp_sentinel.checks.directory_listing import DirectoryListingCheck


async def _run(check, site):
    target = Target.parse("https://example.com", authorized=True)
    async with RateLimitedClient(STANDARD, transport=site.transport) as client:
        ctx = CheckContext(target=target, client=client, profile=STANDARD)
        return await check.run(ctx)


async def test_wp_version_detects_and_flags_generator(mock_site):
    site = mock_site()
    site.add("/", text='<meta name="generator" content="WordPress 6.4.2" /> '
                        '<link href="/wp-content/themes/x/style.css">')
    site.add("/readme.html", status=404, text="nope")
    findings = await _run(WordPressVersionCheck(), site)
    titles = [f.title for f in findings]
    assert any("generator meta tag" in t for t in titles)
    assert any(t.startswith("WordPress detected") and "6.4.2" in t for t in titles)


async def test_wp_version_flags_readme(mock_site):
    site = mock_site()
    site.add("/", text="<html><body>/wp-includes/ here</body></html>")
    site.add("/readme.html", text="<h1>WordPress</h1> Version 6.1")
    findings = await _run(WordPressVersionCheck(), site)
    assert any("readme.html" in f.title for f in findings)


async def test_wp_version_no_wordpress(mock_site):
    site = mock_site()
    site.add("/", text="<html><body>just a static site</body></html>")
    findings = await _run(WordPressVersionCheck(), site)
    assert findings == []


async def test_security_headers_all_missing(mock_site):
    site = mock_site()
    site.add("/", text="<html></html>")
    findings = await _run(SecurityHeadersCheck(), site)
    titles = {f.title for f in findings}
    assert "Missing HSTS header" in titles
    assert "Missing Content-Security-Policy header" in titles
    assert len(findings) == 5


async def test_security_headers_present(mock_site):
    site = mock_site()
    site.add(
        "/",
        text="<html></html>",
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
        },
    )
    findings = await _run(SecurityHeadersCheck(), site)
    assert findings == []


async def test_xmlrpc_enabled(mock_site):
    site = mock_site()
    site.add("/xmlrpc.php", status=405,
             text="XML-RPC server accepts POST requests only.")
    findings = await _run(XmlRpcCheck(), site)
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"


async def test_xmlrpc_disabled(mock_site):
    site = mock_site()
    site.add("/xmlrpc.php", status=403, text="Forbidden")
    findings = await _run(XmlRpcCheck(), site)
    assert findings == []


async def test_user_enum_rest_and_author(mock_site):
    site = mock_site()
    site.add("/wp-json/wp/v2/users",
             text='[{"id":1,"slug":"admin"},{"id":2,"slug":"editor"}]')
    site.add("/?author=1", status=301,
             headers={"Location": "https://example.com/author/admin/"})
    findings = await _run(UserEnumerationCheck(), site)
    titles = {f.title for f in findings}
    assert "Usernames enumerable via REST API" in titles
    assert "Usernames enumerable via author archives" in titles


async def test_user_enum_none(mock_site):
    site = mock_site()
    site.add("/wp-json/wp/v2/users", status=401, text="unauthorized")
    site.add("/?author=1", status=404)
    findings = await _run(UserEnumerationCheck(), site)
    assert findings == []


async def test_sensitive_files_env_exposed(mock_site):
    site = mock_site()
    site.add("/.env", text="DB_PASSWORD=secret\nAPI_KEY=abc")
    findings = await _run(SensitiveFilesCheck(), site)
    assert any(f.title == "Exposed .env file" and f.severity.value == "critical"
               for f in findings)


async def test_sensitive_files_soft_404_ignored(mock_site):
    site = mock_site()
    # A themed 404 returns 200 with HTML and no ".env" marker -> must be ignored.
    site.add("/.env", status=200, text="<!DOCTYPE html><html>404 not found</html>")
    findings = await _run(SensitiveFilesCheck(), site)
    assert findings == []


async def test_sensitive_files_debug_log(mock_site):
    site = mock_site()
    site.add("/wp-content/debug.log", text="[15-Jul-2026] PHP Notice: undefined")
    findings = await _run(SensitiveFilesCheck(), site)
    assert any("debug log" in f.title for f in findings)


async def test_directory_listing(mock_site):
    site = mock_site()
    site.add("/wp-content/uploads/",
             text="<html><head><title>Index of /wp-content/uploads</title></head>")
    findings = await _run(DirectoryListingCheck(), site)
    assert any("uploads" in f.title for f in findings)


def test_active_probe_skipped_in_passive_profile():
    assert SensitiveFilesCheck().applies(PASSIVE) is False
    assert SensitiveFilesCheck().applies(STANDARD) is True
    assert SecurityHeadersCheck().applies(PASSIVE) is True
