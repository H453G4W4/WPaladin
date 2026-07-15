# Writing checks

A **check** is a self-contained, non-destructive probe. Adding one is the
primary way to extend WP-Sentinel.

## The contract

Subclass `wp_sentinel.checks.base.Check`, set `id` and `name`, implement the
async `run`, and register an instance.

```python
from wp_sentinel.checks.base import Check, CheckContext, register
from wp_sentinel.core.finding import Finding, Severity


class RestApiExposureCheck(Check):
    id = "rest-api-index"          # stable, unique, kebab-case
    name = "REST API index exposure"
    requires_active_probes = False # True if it makes extra, non-core requests

    async def run(self, ctx: CheckContext) -> list[Finding]:
        resp = await ctx.client.get(ctx.target.url_for("wp-json/"))
        if resp is None or resp.status_code != 200:
            return []
        return [
            Finding(
                check_id=self.id,
                title="REST API index is publicly reachable",
                severity=Severity.INFO,
                description="The /wp-json/ index enumerates available routes.",
                remediation="Restrict routes you don't expose publicly.",
                url=resp.url,
                evidence="HTTP 200 at /wp-json/",
            )
        ]


register(RestApiExposureCheck())
```

Then import your module in `wp_sentinel/checks/__init__.py` (or from your own
package) so registration runs.

## `CheckContext`

| Field     | Purpose |
|-----------|---------|
| `target`  | `Target` — use `target.url_for("path")` to build URLs |
| `client`  | `RateLimitedClient` — `await client.get(url)` / `.head(url)` |
| `profile` | The active `Profile` (concurrency, timeouts, `active_probes`) |

`client.get(...)` returns a `Response` (with `.status_code`, `.text`,
`.header(name)`, `.url`) or **`None`** on a network error. Always handle `None`.

## Rules of the road

1. **Non-destructive only.** GET/HEAD to read state. No writes, no logins, no
   exploitation, no payloads designed to evade detection. Checks that would
   attack or evade will not be accepted.
2. **Confirm before flagging.** Guard against soft-404s (a `200` with an HTML
   error page). Match on a real marker in the body, as `sensitive_files.py`
   does with its `marker` field.
3. **Right-size severity.** Reserve CRITICAL/HIGH for direct credential/secret
   exposure or clear compromise. Info-disclosure that merely *aids* an attacker
   is usually LOW/MEDIUM.
4. **Actionable remediation.** Every finding must tell the operator exactly how
   to fix it.
5. **Minimal evidence.** Put a short confirmation string in `evidence` — never
   full response bodies or secret values.
6. **Mark active probes.** If your check requests non-core paths, set
   `requires_active_probes = True` so it's skipped in the `passive` profile.

## Testing your check

Use the `mock_site` fixture (see `tests/conftest.py`) to route requests without
a network:

```python
async def test_rest_api_index(mock_site):
    site = mock_site()
    site.add("/wp-json/", text='{"routes": {}}')
    # ... build a Target(authorized=True) + RateLimitedClient(transport=site.transport)
    # ... assert on the returned findings
```

See `tests/test_checks.py` for the `_run(check, site)` helper pattern.
