"""Detect an exposed XML-RPC endpoint.

``xmlrpc.php`` is enabled by default and, while a legitimate API, is frequently
abused for brute-force amplification (``system.multicall``) and pingback-based
SSRF/DDoS. This check only performs a benign GET to detect exposure; it does not
send any ``system.multicall`` or authentication attempts.
"""

from __future__ import annotations

from .base import Check, CheckContext, register
from ..core.finding import Finding, Severity


class XmlRpcCheck(Check):
    id = "xmlrpc"
    name = "XML-RPC exposure"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        url = ctx.target.url_for("xmlrpc.php")
        resp = await ctx.client.get(url)
        if resp is None:
            return []

        # A live endpoint answers GET with a 405 and the classic notice.
        notice = "XML-RPC server accepts POST requests only"
        looks_enabled = resp.status_code in (200, 405) and notice in resp.text
        if not looks_enabled:
            return []

        return [
            Finding(
                check_id=self.id,
                title="XML-RPC endpoint is enabled",
                severity=Severity.MEDIUM,
                description=(
                    "xmlrpc.php is publicly reachable. It can be abused for "
                    "brute-force amplification via system.multicall and for "
                    "pingback-based SSRF/DDoS reflection."
                ),
                remediation=(
                    "If you do not use XML-RPC (Jetpack, remote publishing, "
                    "pingbacks), disable it: block xmlrpc.php at the web server, "
                    "or add 'add_filter(\"xmlrpc_enabled\", \"__return_false\");'. "
                    "If needed, at minimum disable pingbacks."
                ),
                url=resp.url,
                evidence=f"HTTP {resp.status_code}: {notice}",
                references=["https://developer.wordpress.org/apis/xml-rpc/"],
            )
        ]


register(XmlRpcCheck())
