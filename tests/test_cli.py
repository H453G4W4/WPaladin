"""Tests for the CLI: argument parsing, subcommands, scan flow, exit codes."""

from __future__ import annotations

import asyncio

import pytest

from wp_sentinel import cli
from wp_sentinel.core.finding import Finding, Severity
from wp_sentinel.core.scanner import ScanResult
from wp_sentinel.core.target import Target


def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "wp-sentinel" in capsys.readouterr().out


def test_checks_subcommand(capsys):
    assert cli.main(["checks"]) == 0
    out = capsys.readouterr().out
    assert "security-headers" in out and "cookies" in out


def test_profiles_subcommand(capsys):
    assert cli.main(["profiles"]) == 0
    assert "standard" in capsys.readouterr().out


def _fake_result(findings):
    r = ScanResult(target=Target.parse("https://example.com", authorized=True),
                   profile_name="standard")
    r.findings = findings
    r.checks_run = ["security-headers"]
    r.completed_at = 0.5
    return r


class _FakeScanner:
    def __init__(self, result):
        self._result = result

    async def scan(self, target, profile, *, transport=None):
        return self._result


def _run_scan(monkeypatch, argv, result):
    monkeypatch.setattr(cli, "Scanner", lambda: _FakeScanner(result))
    monkeypatch.setattr(cli, "_confirm_authorization", lambda url, yes: True)
    args = cli.build_parser().parse_args(argv)
    return asyncio.run(cli._run_scan(args))


def test_scan_prints_json(monkeypatch, capsys):
    result = _fake_result([Finding("c", "t", Severity.LOW, "d", "r")])
    code = _run_scan(monkeypatch, ["scan", "example.com", "--i-am-authorized"], result)
    assert code == 0
    assert '"tool": "wp-sentinel"' in capsys.readouterr().out


def test_scan_writes_report_file(monkeypatch, tmp_path, capsys):
    out = tmp_path / "report.html"
    result = _fake_result([Finding("c", "t", Severity.HIGH, "d", "r")])
    code = _run_scan(
        monkeypatch,
        ["scan", "example.com", "--i-am-authorized", "--format", "html",
         "-o", str(out)],
        result,
    )
    assert code == 0
    assert out.exists() and "<!DOCTYPE html>" in out.read_text()
    assert "Wrote html report" in capsys.readouterr().out


def test_scan_fail_on_threshold(monkeypatch):
    high = _fake_result([Finding("c", "t", Severity.HIGH, "d", "r")])
    code = _run_scan(
        monkeypatch,
        ["scan", "example.com", "--i-am-authorized", "--fail-on", "high"],
        high,
    )
    assert code == 10

    low = _fake_result([Finding("c", "t", Severity.LOW, "d", "r")])
    code = _run_scan(
        monkeypatch,
        ["scan", "example.com", "--i-am-authorized", "--fail-on", "high"],
        low,
    )
    assert code == 0


def test_scan_invalid_target(monkeypatch, capsys):
    result = _fake_result([])
    monkeypatch.setattr(cli, "_confirm_authorization", lambda url, yes: True)
    args = cli.build_parser().parse_args(["scan", "ftp://x", "--i-am-authorized"])
    assert asyncio.run(cli._run_scan(args)) == 2
    assert "Invalid target" in capsys.readouterr().err


def test_scan_authorization_refused(monkeypatch, capsys):
    # No --i-am-authorized and a non-interactive confirm => refused (exit 3).
    monkeypatch.setattr(cli, "_confirm_authorization", lambda url, yes: False)
    args = cli.build_parser().parse_args(["scan", "example.com"])
    assert asyncio.run(cli._run_scan(args)) == 3


def test_serve_invokes_uvicorn(monkeypatch, capsys):
    import uvicorn

    called = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: called.update(kw))
    args = cli.build_parser().parse_args(["serve", "--port", "9999"])
    assert cli.main(["serve", "--port", "9999"]) == 0
    assert called.get("port") == 9999
