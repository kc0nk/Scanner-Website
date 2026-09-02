from __future__ import annotations

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class CORSModule(ExploitModule):
    name = "CORS"
    category = "protocol"

    async def run(self, ctx):
        evidence = []
        endpoint = ctx.session.current_url or ctx.target.url
        probes = get_payloads(self.name)
        for payload in probes:
            header = {}
            if ":" in payload:
                key, value = payload.split(":", 1)
                header[key.strip()] = value.strip()
            else:
                continue
            try:
                r = await ctx.http.request("GET", endpoint, headers=header, follow_redirects=False)
                allow_origin = r.headers.get("access-control-allow-origin", "")
                allow_credentials = r.headers.get("access-control-allow-credentials", "")
                evidence.append(f"{endpoint} [{payload}] -> {r.status_code}; ACAO={allow_origin!r}; ACAC={allow_credentials!r}")
                if allow_origin in {header.get("Origin", ""), "*"}:
                    confidence = "high" if allow_credentials.lower() == "true" else "medium"
                    ctx.add_finding(endpoint, payload, self.name, f"HTTP {r.status_code}; Access-Control-Allow-Origin={allow_origin}; credentials={allow_credentials or 'absent'}", confidence=confidence)
                    evidence.append(f"[finding] {endpoint} [{payload}] -> CORS policy weakness; continuing remaining CORS probes")
            except Exception as exc:
                evidence.append(str(exc))
        return ExploitResult(self.name, "no-signal", "CORS probes completed (all payloads tested)", evidence="\n".join(evidence[:20]))
