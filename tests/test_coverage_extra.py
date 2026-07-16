"""Small, targeted tests closing coverage gaps in CLI, base, http, reports."""

from __future__ import annotations

import argparse

import httpx
import pytest

from wp_sentinel import cli
from wp_sentinel.checks.base import Check, all_checks, clear_registry, register
from wp_sentinel.core.http import RateLimitedClient
from wp_sentinel.core.profile import PASSIVE, STANDARD
from wp_sentinel.core.scanner import ScanResult
from wp_sentinel.core.target import Target
from wp_sentinel.report import render


# ---- CLI helpers ----

def test_confirm_authorization_assume_yes():
    assert cli._confirm_authorization("https://x", True) is True


def test_confirm_authorization_non_tty(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli._confirm_authorization("https://x", False) is False


def test_run_scan_unknown_profile(monkeypatch, capsys):
    import asyncio

    args = argparse.Namespace(
        url="example.com", profile="bogus", format="json", output=None,
        i_am_authorized=True, fail_on=None,
    )
    assert asyncio.run(cli._run_scan(args)) == 2
    assert "Unknown profile" in capsys.readouterr().err


# ---- check registry error paths ----

def test_register_rejects_empty_and_duplicate_ids():
    class NoId(Check):
        id = ""
        name = "x"

        async def run(self, ctx):
            return []

    with pytest.raises(ValueError):
        register(NoId())

    class Dup(Check):
        id = "security-headers"  # already registered
        name = "dup"

        async def run(self, ctx):
            return []

    with pytest.raises(ValueError):
        register(Dup())


def test_clear_registry_isolated():
    # Operate on a throwaway registry snapshot by clearing and restoring.
    saved = all_checks()
    try:
        clear_registry()
        assert all_checks() == []
    finally:
        for chk in saved:
            register(chk)
    assert len(all_checks()) == len(saved)


def test_check_applies_active_probe_gate():
    class Probe(Check):
        id = "probe-x"
        name = "p"
        requires_active_probes = True

        async def run(self, ctx):
            return []

    p = Probe()
    assert p.applies(STANDARD) is True
    assert p.applies(PASSIVE) is False


# ---- http error handling ----

async def test_http_get_returns_none_on_error():
    def boom(request):
        raise httpx.ConnectError("refused", request=request)

    async with RateLimitedClient(STANDARD, transport=httpx.MockTransport(boom)) as c:
        assert await c.get("https://example.com") is None
        assert await c.head("https://example.com") is None


# ---- markdown edge branches ----

def _empty_result():
    r = ScanResult(target=Target.parse("https://example.com"), profile_name="passive")
    r.checks_run = ["a"]
    return r


def test_markdown_no_findings_and_references():
    md = render("markdown", _empty_result())
    assert "No findings" in md and "grade **A**" in md
