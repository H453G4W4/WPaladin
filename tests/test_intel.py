"""Tests for the vulnerability-intelligence engine and correlation check."""

from __future__ import annotations

import pytest

from wp_sentinel.core.http import RateLimitedClient
from wp_sentinel.core.profile import STANDARD
from wp_sentinel.core.target import Target
from wp_sentinel.checks.base import CheckContext
from wp_sentinel.checks.known_vulns import KnownVulnerabilityCheck
from wp_sentinel.intel import parse_version, VulnerabilityDatabase
from wp_sentinel.intel.advisories import Advisory, version_lt


# ---- version parsing / comparison ----

@pytest.mark.parametrize("raw,expected", [
    ("5.8.2", (5, 8, 2)),
    ("v1.2", (1, 2)),
    ("1.4.3-beta", (1, 4, 3)),
    ("2.0", (2, 0)),
    ("", ()),
    ("notaversion", ()),
])
def test_parse_version(raw, expected):
    assert parse_version(raw) == expected


@pytest.mark.parametrize("a,b,lt", [
    ("5.8.2", "5.8.3", True),
    ("5.8.3", "5.8.3", False),
    ("4.7", "4.7.2", True),       # zero-padded: 4.7.0 < 4.7.2
    ("5.9", "5.8.3", False),
    ("1.10.0", "1.9.0", False),   # numeric, not lexical
])
def test_version_lt(a, b, lt):
    assert version_lt(a, b) is lt


# ---- advisory affected-range model ----

def _adv(**kw):
    base = dict(id="x", component_type="plugin", slug="p", title="t", severity="high")
    base.update(kw)
    return Advisory(**base)


def test_advisory_range_bounds():
    adv = _adv(introduced="1.0.0", fixed="1.4.3")
    assert adv.affects("1.0.0") is True      # inclusive lower bound
    assert adv.affects("1.4.2") is True
    assert adv.affects("1.4.3") is False     # exclusive upper bound (patched)
    assert adv.affects("0.9.0") is False
    assert adv.affects("2.0.0") is False


def test_advisory_open_bounds():
    assert _adv(introduced=None, fixed="2.0").affects("1.5") is True
    assert _adv(introduced="3.0", fixed=None).affects("3.1") is True
    assert _adv(introduced="3.0", fixed=None).affects("2.9") is False
    assert _adv(introduced=None, fixed=None).affects("9.9") is True
    assert _adv(introduced="1.0", fixed="2.0").affects("bad") is False


# ---- database ----

def test_database_indexing_and_match():
    db = VulnerabilityDatabase([
        _adv(id="a", slug="alpha", fixed="2.0"),
        _adv(id="b", slug="alpha", introduced="2.0", fixed="3.0"),
        _adv(id="c", component_type="core", slug="wordpress", fixed="5.8.3"),
    ])
    assert len(db) == 3
    hits = db.matches("plugin", "Alpha", "1.5")   # slug is case-insensitive
    assert [h.id for h in hits] == ["a"]
    assert db.matches("plugin", "alpha", "2.5")[0].id == "b"
    assert db.matches("plugin", "alpha", "9.0") == []
    assert db.matches("core", "wordpress", "5.8.0")[0].id == "c"


def test_bundled_default_dataset_loads():
    db = VulnerabilityDatabase.default()
    assert len(db) >= 3
    # The real core REST advisory should match a vulnerable 4.7.0.
    hits = db.matches("core", "wordpress", "4.7.0")
    assert any(h.cve == "CVE-2017-1001000" for h in hits)
    # ...and not match a patched 5.9.
    assert db.matches("core", "wordpress", "5.9") == []


def test_from_json_roundtrip():
    text = '{"advisories":[{"id":"z","component_type":"theme","slug":"twenty",' \
           '"title":"t","severity":"low","fixed":"2.0","cvss":3.1}]}'
    db = VulnerabilityDatabase.from_json(text)
    assert db.matches("theme", "twenty", "1.0")[0].cvss == 3.1


# ---- correlation check (end to end, mocked site + injected DB) ----

async def _run(check, site):
    target = Target.parse("https://example.com", authorized=True)
    async with RateLimitedClient(STANDARD, transport=site.transport) as client:
        ctx = CheckContext(target=target, client=client, profile=STANDARD)
        return await check.run(ctx)


async def test_known_vulns_core_and_plugin(mock_site):
    db = VulnerabilityDatabase([
        _adv(id="core-x", component_type="core", slug="wordpress",
             title="core RCE", severity="critical", cvss=9.8,
             cve="CVE-2099-0001", introduced="4.7.0", fixed="4.7.2"),
        _adv(id="plug-x", component_type="plugin", slug="contact-form-7",
             title="CF7 XSS", severity="medium", cvss=6.1, fixed="5.9.3"),
    ])
    site = mock_site()
    site.add("/", text='<meta name="generator" content="WordPress 4.7.0">'
                       '<link href="/wp-content/plugins/contact-form-7/x.css">')
    site.add("/wp-content/plugins/contact-form-7/readme.txt",
             text="Stable tag: 5.9.2")
    findings = await _run(KnownVulnerabilityCheck(database=db), site)
    titles = " ".join(f.title for f in findings)
    assert "core RCE" in titles and "CF7 XSS" in titles
    core = next(f for f in findings if "core RCE" in f.title)
    assert core.cve == "CVE-2099-0001" and core.cvss == 9.8
    assert core.severity.value == "critical" and core.owasp == "A06:2021"


async def test_known_vulns_patched_version_no_finding(mock_site):
    db = VulnerabilityDatabase([
        _adv(id="core-x", component_type="core", slug="wordpress",
             title="old bug", fixed="4.7.2", introduced="4.7.0"),
    ])
    site = mock_site()
    site.add("/", text='<meta name="generator" content="WordPress 6.4.2"> /wp-content/')
    site.add("/readme.html", status=404)
    assert await _run(KnownVulnerabilityCheck(database=db), site) == []


async def test_known_vulns_empty_db_is_noop(mock_site):
    site = mock_site()
    site.add("/", text='<meta name="generator" content="WordPress 4.7.0">')
    assert await _run(KnownVulnerabilityCheck(database=VulnerabilityDatabase([])), site) == []
