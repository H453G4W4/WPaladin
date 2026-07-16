"""Tests for the Phase 3 checks: cookies, CORS, server/tech, WP endpoints, TLS."""

from __future__ import annotations

import datetime as dt

import pytest

from wp_sentinel.core.http import RateLimitedClient
from wp_sentinel.core.profile import STANDARD
from wp_sentinel.core.target import Target
from wp_sentinel.checks.base import CheckContext
from wp_sentinel.checks.cookies import CookieSecurityCheck
from wp_sentinel.checks.cors import CorsCheck
from wp_sentinel.checks.server_tech import ServerTechCheck
from wp_sentinel.checks.wp_endpoints import InstallScriptCheck, RobotsSitemapCheck
from wp_sentinel.checks.tls import TlsCheck, _TlsInfo


async def _run(check, site, target_url="https://example.com"):
    target = Target.parse(target_url, authorized=True)
    async with RateLimitedClient(STANDARD, transport=site.transport) as client:
        ctx = CheckContext(target=target, client=client, profile=STANDARD)
        return await check.run(ctx)


# ---- cookies ----

async def test_cookie_missing_flags(mock_site):
    site = mock_site()
    site.add("/", text="<html></html>",
             headers={"Set-Cookie": "wordpress_sec=abc; Path=/"})
    findings = await _run(CookieSecurityCheck(), site)
    assert len(findings) == 1
    assert "Secure" in findings[0].title and "HttpOnly" in findings[0].title


async def test_cookie_fully_hardened(mock_site):
    site = mock_site()
    site.add("/", text="<html></html>", headers={
        "Set-Cookie": "sess=abc; Secure; HttpOnly; SameSite=Lax"})
    assert await _run(CookieSecurityCheck(), site) == []


async def test_cookie_no_cookies(mock_site):
    site = mock_site()
    site.add("/", text="<html></html>")
    assert await _run(CookieSecurityCheck(), site) == []


# ---- CORS ----

async def test_cors_reflect_with_credentials_high(mock_site):
    site = mock_site()
    site.add("/", text="ok", headers={
        "Access-Control-Allow-Origin": "https://wp-sentinel-cors-probe.invalid",
        "Access-Control-Allow-Credentials": "true",
    })
    findings = await _run(CorsCheck(), site)
    assert len(findings) == 1 and findings[0].severity.value == "high"


async def test_cors_wildcard_low(mock_site):
    site = mock_site()
    site.add("/", text="ok", headers={"Access-Control-Allow-Origin": "*"})
    findings = await _run(CorsCheck(), site)
    assert len(findings) == 1 and findings[0].severity.value == "low"


async def test_cors_absent(mock_site):
    site = mock_site()
    site.add("/", text="ok")
    assert await _run(CorsCheck(), site) == []


# ---- server / tech ----

async def test_server_tech_cloudflare_and_powered_by(mock_site):
    site = mock_site()
    site.add("/", text="ok", headers={
        "Server": "cloudflare", "CF-Ray": "abc", "X-Powered-By": "PHP/8.1.2"})
    findings = await _run(ServerTechCheck(), site)
    titles = {f.title for f in findings}
    assert "Server / CDN / hosting technology disclosed" in titles
    assert "X-Powered-By discloses stack version" in titles
    disclosed = next(f for f in findings if "hosting technology" in f.title)
    assert "Cloudflare" in disclosed.evidence


async def test_server_tech_none(mock_site):
    site = mock_site()
    site.add("/", text="ok")
    assert await _run(ServerTechCheck(), site) == []


# ---- WordPress endpoints ----

async def test_install_script_setup(mock_site):
    site = mock_site()
    site.add("/wp-admin/install.php",
             text="<html>WordPress &rsaquo; Installation ... install</html>")
    findings = await _run(InstallScriptCheck(), site)
    assert len(findings) == 1 and findings[0].severity.value == "medium"


async def test_install_script_already_installed(mock_site):
    site = mock_site()
    site.add("/wp-admin/install.php",
             text="<html>WordPress already installed.</html>")
    findings = await _run(InstallScriptCheck(), site)
    assert len(findings) == 1 and findings[0].severity.value == "low"


async def test_robots_discloses_paths(mock_site):
    site = mock_site()
    site.add("/robots.txt",
             text="User-agent: *\nDisallow: /wp-admin/\nDisallow: /backup/\n")
    findings = await _run(RobotsSitemapCheck(), site)
    assert len(findings) == 1 and "wp-admin" in findings[0].evidence


async def test_robots_benign(mock_site):
    site = mock_site()
    site.add("/robots.txt", text="User-agent: *\nDisallow: /cgi-bin/\n")
    assert await _run(RobotsSitemapCheck(), site) == []


# ---- TLS logic (probe stubbed per-scenario) ----

async def test_tls_deprecated_protocol(mock_site, monkeypatch):
    monkeypatch.setattr(
        TlsCheck, "_probe",
        staticmethod(lambda h, p, t: _TlsInfo(protocol="TLSv1", not_after=None)),
    )
    site = mock_site()
    findings = await _run(TlsCheck(), site)
    assert any("Deprecated TLS protocol" in f.title for f in findings)


async def test_tls_expired_cert(mock_site, monkeypatch):
    past = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
    monkeypatch.setattr(
        TlsCheck, "_probe",
        staticmethod(lambda h, p, t: _TlsInfo(protocol="TLSv1.3", not_after=past)),
    )
    site = mock_site()
    findings = await _run(TlsCheck(), site)
    assert any(f.title == "TLS certificate has expired" for f in findings)


async def test_tls_handshake_error(mock_site, monkeypatch):
    monkeypatch.setattr(
        TlsCheck, "_probe",
        staticmethod(lambda h, p, t: _TlsInfo(None, None, error="conn refused")),
    )
    site = mock_site()
    findings = await _run(TlsCheck(), site)
    assert any("handshake failed" in f.title for f in findings)
