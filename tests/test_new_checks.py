"""Tests for the checks added alongside the dashboard."""

from __future__ import annotations

import pytest

from wp_sentinel.core.http import RateLimitedClient
from wp_sentinel.core.profile import STANDARD
from wp_sentinel.core.target import Target
from wp_sentinel.checks.base import CheckContext
from wp_sentinel.checks.plugins import PluginEnumerationCheck
from wp_sentinel.checks.misc_endpoints import (
    RestApiIndexCheck,
    WpCronCheck,
    SecurityTxtCheck,
)
from wp_sentinel.checks.tls import TlsCheck


async def _run(check, site, target_url="https://example.com"):
    target = Target.parse(target_url, authorized=True)
    async with RateLimitedClient(STANDARD, transport=site.transport) as client:
        ctx = CheckContext(target=target, client=client, profile=STANDARD)
        return await check.run(ctx)


async def test_plugin_enumeration_and_version(mock_site):
    site = mock_site()
    site.add(
        "/",
        text='<link href="/wp-content/plugins/contact-form-7/x.css">'
        '<script src="/wp-content/plugins/woocommerce/y.js"></script>',
    )
    site.add(
        "/wp-content/plugins/contact-form-7/readme.txt",
        text="=== Contact Form 7 ===\nStable tag: 5.9.2\n",
    )
    site.add("/wp-content/plugins/woocommerce/readme.txt", status=404)
    findings = await _run(PluginEnumerationCheck(), site)
    titles = [f.title for f in findings]
    assert any("2 plugin(s) discoverable" in t for t in titles)
    assert any("contact-form-7" in t and "5.9.2" in t for t in titles)


async def test_plugin_enumeration_none(mock_site):
    site = mock_site()
    site.add("/", text="<html>no plugins here</html>")
    assert await _run(PluginEnumerationCheck(), site) == []


async def test_rest_api_index(mock_site):
    site = mock_site()
    site.add("/wp-json/", text='{"name":"Site","routes":{"/wp/v2":{}}}')
    findings = await _run(RestApiIndexCheck(), site)
    assert len(findings) == 1 and findings[0].check_id == "rest-api-index"


async def test_wp_cron_accessible(mock_site):
    site = mock_site()
    site.add("/wp-cron.php", status=200, text="")
    findings = await _run(WpCronCheck(), site)
    assert len(findings) == 1 and findings[0].severity.value == "low"


async def test_security_txt_present_no_finding(mock_site):
    site = mock_site()
    site.add("/.well-known/security.txt", text="Contact: mailto:sec@example.com")
    assert await _run(SecurityTxtCheck(), site) == []


async def test_security_txt_absent(mock_site):
    site = mock_site()
    site.add("/.well-known/security.txt", status=404)
    site.add("/security.txt", status=404)
    findings = await _run(SecurityTxtCheck(), site)
    assert len(findings) == 1 and findings[0].severity.value == "info"


async def test_tls_flags_plain_http(mock_site):
    site = mock_site()
    findings = await _run(TlsCheck(), site, target_url="http://example.com")
    assert len(findings) == 1
    assert findings[0].title == "Site is not served over HTTPS"
    assert findings[0].severity.value == "high"
