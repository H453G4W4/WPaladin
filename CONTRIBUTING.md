# Contributing

Thanks for your interest in WP-Sentinel.

## Scope policy (please read first)

WP-Sentinel is a **defensive / authorized-audit** tool. Contributions that add
non-destructive detection, clearer reporting, remediation guidance, or better
ergonomics are very welcome.

Contributions that add **exploitation** or **defense-evasion** capabilities will
be declined — this includes reverse shells, RCE/SQLi/LFI execution, database
extraction, backdoor/persistence injection, WAF-bypass or payload-mutation
engines, IP-reputation bypass, proxy/Tor rotation for anonymity, "distributed"
or botnet-style scanning, and CAPTCHA solving. This boundary is intentional and
not up for case-by-case negotiation. See `README.md` → *Scope*.

## Development setup

```bash
pip install -e ".[dev]"
pytest
```

The test suite runs fully offline (mocked HTTP). Please add tests for any new
check or behavior; see [`docs/WRITING_CHECKS.md`](docs/WRITING_CHECKS.md).

## Standards

- Target Python 3.11+; use type hints and `async`/`await` for I/O.
- Keep checks non-destructive and self-contained (one file per check).
- Every `Finding` needs a real severity, a clear description, and actionable
  remediation.
- Match the surrounding style; keep functions small and readable.

## Pull requests

1. Branch from the default branch.
2. Include tests and, if you added a check, a line in the README's in-scope list.
3. Keep the diff focused; explain the "why" in the PR description.
