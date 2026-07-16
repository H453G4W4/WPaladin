# WP-Sentinel

**A non-destructive, authorization-gated WordPress security auditor.**

WP-Sentinel scans a WordPress site you own or are explicitly authorized to test
and reports misconfigurations and information-disclosure issues — missing
security headers, exposed sensitive files, username enumeration, XML-RPC
exposure, and version disclosure — with severity ratings and concrete
remediation guidance.

It is built for **defenders and authorized auditors**. Every check is passive or
non-destructive: WP-Sentinel observes and reports. It does **not** exploit
vulnerabilities, attack targets at scale, or evade defenses.

---

## Scope: what this tool is, and is not

This project deliberately implements the *defensive / authorized-audit* subset
of WordPress security tooling. That scope is a feature, not a limitation.

**In scope (implemented):**

- WordPress detection and version-disclosure reporting
- HTTP security-header analysis — HSTS (+ preload readiness), CSP (+ weak-directive
  detection), Permissions-Policy, COOP/COEP/CORP, X-Frame-Options, and more
- Cookie attribute analysis (Secure / HttpOnly / SameSite)
- CORS policy analysis (reflected-origin-with-credentials, wildcard)
- TLS/SSL analysis (HTTPS enforcement, cert expiry, deprecated protocols)
- Server / CDN / hosting detection from ordinary response headers
- XML-RPC exposure detection
- Username enumeration detection (REST API, author archives)
- Plugin enumeration and plugin version disclosure (via public `readme.txt`)
- REST API index exposure, externally triggerable `wp-cron.php`, `security.txt`,
  install-script exposure, robots.txt path disclosure
- Exposed sensitive-file detection (`.env`, `.git`, `.svn`, config backups, DB
  dumps, lockfiles, editor swap files, debug logs, …)
- Directory-listing detection
- Severity + CVSS-style scoring, **OWASP Top 10 / CWE mapping**, and a **0–100
  hardening score** with a letter grade
- Reports in **JSON, HTML, CSV, SARIF, and Markdown**
- **A browser dashboard + REST/WebSocket API** to launch scans and browse findings
- An authorization gate and polite, rate-limited requests by default

**Intentionally out of scope (and not accepted as contributions):**

Actual exploitation (reverse shells, RCE/SQLi/LFI execution, DB extraction),
persistence/backdoor injection, and *defense-evasion* features (WAF-bypass
generation, payload mutation to avoid detection, IP-reputation bypass,
"botnet-like" distributed scanning, CAPTCHA solving, proxy rotation for
anonymity). These are attack-and-evade capabilities aimed at operating against
targets without their defenders' knowledge, and they are out of scope for this
project regardless of framing.

If you are running an authorized penetration test that requires exploitation,
use a purpose-built framework under your engagement's rules of engagement.
WP-Sentinel's job is to find and clearly explain the issues so they can be
fixed.

---

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/h453g4w4/wpaladin.git
cd wpaladin
pip install -e ".[dev]"     # or: pip install -e .  (runtime only)
```

## Quick start

```bash
# Scan a site you are authorized to test (interactive confirmation on a TTY):
wp-sentinel scan https://your-site.example

# Non-interactive: assert authorization explicitly
wp-sentinel scan your-site.example --i-am-authorized

# Choose a profile and write an HTML report
wp-sentinel scan your-site.example --i-am-authorized \
    --profile thorough --format html -o report.html

# CI-friendly: exit non-zero if anything HIGH or worse is found
wp-sentinel scan your-site.example --i-am-authorized --fail-on high
```

List what's available:

```bash
wp-sentinel checks      # all registered checks
wp-sentinel profiles    # passive / standard / thorough
```

You can also run it as a module: `python -m wp_sentinel ...`.

## Browser dashboard & API

WP-Sentinel ships a web dashboard for launching scans and browsing findings,
backed by a REST + WebSocket API.

```bash
pip install -e ".[api]"           # or ".[dev]"
wp-sentinel serve                 # http://127.0.0.1:8000
wp-sentinel serve --host 0.0.0.0 --port 8080
```

Open the URL in a browser: enter a target, pick a profile, tick the
authorization box, and start. Running scans update live; completed scans show
findings grouped by severity with remediation, plus one-click JSON/HTML/CSV
report downloads.

The API mirrors the CLI's guardrail — `POST /api/v1/scans` is rejected with
**403** unless the request body includes `"authorized": true`.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/scans` | Start a scan (requires `authorized: true`) |
| GET  | `/api/v1/scans` | List scans |
| GET  | `/api/v1/scans/{id}` | Status + summary |
| GET  | `/api/v1/scans/{id}/findings` | Full findings |
| GET  | `/api/v1/scans/{id}/report?format=html\|json\|csv` | Rendered report |
| WS   | `/api/v1/scans/{id}/ws` | Live status stream |
| GET  | `/api/v1/checks`, `/api/v1/profiles`, `/api/v1/health` | Metadata |

```bash
# Start a scan against a site you are authorized to test
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://your-site.example","authorized":true,"profile":"standard"}'
```

### The authorization gate

`scan` will not run unless you confirm you're authorized:

- On an interactive terminal it prompts you to type `yes`.
- In scripts/CI, pass `--i-am-authorized`.

This is a guardrail, not a legal shield — **only scan systems you own or have
written permission to test.** Unauthorized scanning may be illegal in your
jurisdiction.

## Scan profiles

| Profile    | Concurrency | Delay | Active probes | Use for |
|------------|-------------|-------|---------------|---------|
| `passive`  | 2           | 0.5s  | no            | Low-noise first look |
| `standard` | 4           | 0.2s  | yes           | Default balanced audit |
| `thorough` | 8           | 0.05s | yes           | Faster audit of your own infra |

All profiles are non-destructive. "Active probes" means extra GET requests to
known sensitive paths — never writes or exploits.

## Report formats

- **JSON** (`--format json`) — machine-readable, SIEM-friendly (default)
- **HTML** (`--format html`) — self-contained, shareable report
- **CSV** (`--format csv`) — spreadsheet / ticketing import
- **SARIF** (`--format sarif`) — GitHub code scanning / SARIF-aware tooling
- **Markdown** (`--format markdown` or `md`) — executive summary + technical
  detail for issues, wikis, and PR descriptions

Every finding carries a severity, a representative CVSS score, and (where
applicable) OWASP Top 10 and CWE identifiers. Reports also include an aggregate
**hardening score** (0–100) and letter grade for trend tracking across scans.

## Development

```bash
pip install -e ".[dev]"
pytest            # full suite runs offline (mocked HTTP transport)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design and
[`docs/WRITING_CHECKS.md`](docs/WRITING_CHECKS.md) to add your own checks.

## License

MIT — see [`LICENSE`](LICENSE).
