# Architecture

WP-Sentinel is a small, layered async Python application. The design goals are:
be **non-destructive by construction**, be **easy to extend** with new checks,
and keep results **consistent and machine-readable**.

## Component overview

```
        wp_sentinel.cli
              │  parses args, enforces the authorization prompt
              ▼
        core.scanner.Scanner
              │  runs applicable checks concurrently
   ┌──────────┼───────────────────────────┐
   ▼          ▼                            ▼
core.target  core.http                 checks.base.Check  ── registry
 Target      RateLimitedClient          (subclasses)
 (auth gate) (concurrency + delay)         │
                                           ▼
                                   core.finding.Finding
                                           │
                                           ▼
                                   report.{json,html,csv}
```

## Layers

### `core.target` — Target & authorization
`Target.parse()` normalizes user input (adds a scheme, lowercases the host,
strips path/query). `Target.require_authorization()` is the gate the scanner
calls before doing anything; without an acknowledged authorization it raises
`AuthorizationError`.

### `core.http` — Polite HTTP
`RateLimitedClient` wraps `httpx.AsyncClient` with:
- a **semaphore** capping concurrent in-flight requests, and
- a shared clock enforcing a **minimum delay** between request starts.

It uses one honest `User-Agent` and does not follow redirects (so checks can
inspect `Location` headers). Network/timeout errors return `None` rather than
raising, so one dead endpoint never aborts a scan. A `Response` value object
gives checks a stable, framework-agnostic view (status, headers, text).

### `checks` — The check registry
A `Check` is an abstract, self-contained probe with a stable `id`, a `name`, and
an async `run(ctx) -> list[Finding]`. Checks register themselves into a global
ordered registry on import. `requires_active_probes = True` marks checks that
issue extra requests; those are skipped under the `passive` profile via
`Check.applies(profile)`.

Because checks are decoupled and registered dynamically, adding a capability is
purely additive — see [`WRITING_CHECKS.md`](WRITING_CHECKS.md).

### `core.finding` — Findings & scoring
`Finding` is the atomic result: id, title, `Severity`, description, remediation,
and optional url/evidence/cve/cvss/references. `Severity` is an ordered enum
(INFO→CRITICAL) with a representative CVSS v3.1 base score per level; a finding
may override with an explicit `cvss` when a real CVE score applies.

### `core.scanner` — Orchestration
`Scanner.scan()` enforces the authorization gate, selects checks applicable to
the profile, runs them concurrently with `asyncio.gather(return_exceptions=True)`
(so a raising check is recorded in `result.errors` instead of crashing the run),
and aggregates a `ScanResult` with sorting and severity-count helpers.

### `report` — Renderers
Pure functions from `ScanResult` to a string: `render_json`, `render_html`
(self-contained, escaped), `render_csv`. `report.render(fmt, result)` dispatches
by name.

## Concurrency model

A scan is one async pipeline. All checks share a single `RateLimitedClient`, so
the concurrency cap and politeness delay apply **across the whole scan**, not
per-check. This keeps total request pressure on the target bounded and
predictable regardless of how many checks are registered.

## Testing

The suite is hermetic: `tests/conftest.py` builds an `httpx.MockTransport` from a
small routing table, so checks and full scans are exercised end-to-end without
touching the network.

## Extending toward the larger vision

The layered design leaves clean seams for the *defensive* roadmap items:
scheduled re-scans and CVE monitoring wrap `Scanner`; a REST API is a thin layer
over `Scanner` + `report`; persistence is a matter of serializing `ScanResult`.
None of that requires touching the check contract.
