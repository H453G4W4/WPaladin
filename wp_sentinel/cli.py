"""Command-line interface for WP-Sentinel.

Usage highlights::

    wp-sentinel scan https://example.com --i-am-authorized
    wp-sentinel scan example.com --profile thorough --format html -o report.html
    wp-sentinel checks
    wp-sentinel profiles

The ``scan`` command refuses to run without an explicit authorization flag (or
an interactive "yes" confirmation on a TTY).
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__
from .checks.base import all_checks
from .core.profile import PROFILES, get_profile
from .core.scanner import Scanner
from .core.target import AuthorizationError, Target
from .report import render

# Ensure built-in checks are registered.
from . import checks as _checks  # noqa: F401


def _confirm_authorization(url: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    print(
        f"\nYou are about to scan: {url}\n"
        "Only scan systems you own or are explicitly authorized to test.\n"
        "Unauthorized scanning may be illegal.\n"
    )
    answer = input("Type 'yes' to confirm you are authorized: ").strip().lower()
    return answer == "yes"


async def _run_scan(args: argparse.Namespace) -> int:
    try:
        profile = get_profile(args.profile)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    authorized = _confirm_authorization(args.url, args.i_am_authorized)
    try:
        target = Target.parse(args.url, authorized=authorized)
    except ValueError as exc:
        print(f"Invalid target: {exc}", file=sys.stderr)
        return 2

    scanner = Scanner()
    try:
        result = await scanner.scan(target, profile)
    except AuthorizationError as exc:
        print(str(exc), file=sys.stderr)
        return 3

    output = render(args.format, result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        counts = result.severity_counts()
        summary = ", ".join(
            f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info")
        )
        print(f"Wrote {args.format} report to {args.output}  ({summary})")
    else:
        print(output)

    highest = result.highest_severity
    if args.fail_on and highest is not None and highest.rank >= _rank_for(args.fail_on):
        return 10
    return 0


def _rank_for(severity_name: str) -> int:
    from .core.finding import Severity

    return Severity(severity_name).rank


def _cmd_checks(_: argparse.Namespace) -> int:
    print("Registered checks (non-destructive):\n")
    for check in all_checks():
        active = " [active probe]" if check.requires_active_probes else ""
        print(f"  {check.id:<20} {check.name}{active}")
    return 0


def _cmd_profiles(_: argparse.Namespace) -> int:
    print("Scan profiles:\n")
    for name, profile in PROFILES.items():
        print(f"  {name:<10} concurrency={profile.concurrency} "
              f"delay={profile.delay_seconds}s")
        print(f"             {profile.description}\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp-sentinel",
        description="Non-destructive, authorization-gated WordPress security auditor.",
    )
    parser.add_argument("--version", action="version", version=f"wp-sentinel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a target WordPress site.")
    scan.add_argument("url", help="Target URL or hostname (e.g. https://example.com).")
    scan.add_argument(
        "--profile", default="standard", choices=sorted(PROFILES),
        help="Scan profile (default: standard).",
    )
    scan.add_argument(
        "--format", default="json", choices=["json", "html", "csv"],
        help="Report format (default: json).",
    )
    scan.add_argument("-o", "--output", help="Write the report to a file.")
    scan.add_argument(
        "--i-am-authorized", action="store_true",
        help="Assert you are authorized to test this target (skips the prompt).",
    )
    scan.add_argument(
        "--fail-on", choices=["low", "medium", "high", "critical"], default=None,
        help="Exit with code 10 if any finding meets/exceeds this severity "
             "(useful in CI).",
    )
    scan.set_defaults(func=_run_scan, is_async=True)

    checks_cmd = sub.add_parser("checks", help="List available checks.")
    checks_cmd.set_defaults(func=_cmd_checks, is_async=False)

    profiles_cmd = sub.add_parser("profiles", help="List scan profiles.")
    profiles_cmd.set_defaults(func=_cmd_profiles, is_async=False)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "is_async", False):
        return asyncio.run(args.func(args))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
