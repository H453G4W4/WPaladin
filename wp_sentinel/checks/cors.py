"""CORS misconfiguration detection.

Sends a single benign GET with a foreign ``Origin`` header and inspects the
``Access-Control-Allow-Origin`` / ``-Allow-Credentials`` response. It does not
attempt any cross-origin data theft — it only observes how the server *would*
advertise its CORS policy. Reflecting an arbitrary origin together with
credentials is a classic account-takeover primitive and is flagged HIGH.
"""

from __future__ import annotations

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity

_PROBE_ORIGIN = "https://wp-sentinel-cors-probe.invalid"


class CorsCheck(Check):
    id = "cors"
    name = "CORS policy"
    requires_active_probes = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        resp = await ctx.client.get(
            ctx.target.base_url, headers={"Origin": _PROBE_ORIGIN}
        )
        if resp is None:
            return []

        acao = resp.header("Access-Control-Allow-Origin")
        if not acao:
            return []

        creds = (resp.header("Access-Control-Allow-Credentials") or "").lower() == "true"
        reflects = acao.strip() == _PROBE_ORIGIN
        wildcard = acao.strip() == "*"

        if reflects and creds:
            return [
                Finding(
                    check_id=self.id,
                    title="CORS reflects arbitrary origin with credentials",
                    severity=Severity.HIGH,
                    description=(
                        "The server reflects any Origin in "
                        "Access-Control-Allow-Origin while also allowing "
                        "credentials, letting a malicious site read "
                        "authenticated responses on a victim's behalf."
                    ),
                    remediation=(
                        "Never combine credentialed CORS with a reflected/"
                        "wildcard origin. Allow only a fixed allowlist of trusted "
                        "origins."
                    ),
                    url=resp.url,
                    evidence=f"ACAO reflected '{acao}' with credentials=true",
                    owasp="A05:2021",
                    cwe="CWE-942",
                )
            ]
        if reflects or wildcard:
            return [
                Finding(
                    check_id=self.id,
                    title="Permissive CORS policy",
                    severity=Severity.LOW,
                    description=(
                        f"Access-Control-Allow-Origin is '{acao}', allowing any "
                        "origin to read non-credentialed responses. Lower risk "
                        "without credentials, but still overly broad."
                    ),
                    remediation="Restrict Access-Control-Allow-Origin to trusted origins.",
                    url=resp.url,
                    evidence=f"ACAO: {acao}",
                    owasp="A05:2021",
                    cwe="CWE-942",
                )
            ]
        return []


register(CorsCheck())
