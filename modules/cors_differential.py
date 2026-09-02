from __future__ import annotations

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class CORSDifferentialModule(ExploitModule):
    name = "CORS / Header Differential"
    category = "misconfiguration"

    async def run(self, ctx):
        payloads = get_payloads(self.name)
        requests = ctx.artifacts.get("recon.requests", []) or []
        endpoints = [r.get("url") for r in requests if isinstance(r, dict) and r.get("url")]
        if not endpoints:
            endpoints = [ctx.session.current_url or ctx.target.url]
        evidence = []
        findings = 0
        for endpoint in list(dict.fromkeys(endpoints))[:30]:
            original = ctx.original_request_for("GET", endpoint)
            for idx, payload in enumerate(payloads, 1):
                ctx.logger(f"[payload {idx}/{len(payloads)}] CORS / Header Differential: {payload}")
                try:
                    if ":" in payload:
                        key, value = payload.split(":", 1)
                        r = await ctx.request_original(
                            original,
                            url=endpoint,
                            method=original.get("method") or "GET",
                            headers={key.strip(): value.strip()},
                        )
                    else:
                        r = await ctx.request_original(original, url=endpoint, method=original.get("method") or "GET")
                    acao = r.headers.get("access-control-allow-origin", "")
                    acac = r.headers.get("access-control-allow-credentials", "")
                    ctx.mark_payload(self.name, payload, "tested", f"status={r.status_code}; ACAO={acao}; ACAC={acac}")
                    evidence.append(f"{endpoint} [{payload}] -> {r.status_code}; ACAO={acao!r}; ACAC={acac!r}")
                    if acao in {"*", value.strip() if ":" in payload else ""} and acao:
                        findings += 1
                        ctx.add_finding(
                            endpoint,
                            payload,
                            self.name,
                            f"HTTP {r.status_code}; Access-Control-Allow-Origin={acao}; credentials={acac or 'absent'}",
                            confidence="medium" if acac.lower() != "true" else "high",
                        )
                except Exception as exc:
                    ctx.mark_payload(self.name, payload, "error", str(exc))
                    evidence.append(f"{endpoint} [{payload}] -> error: {exc}")
        return ExploitResult(self.name, "signal" if findings else "no-signal", f"CORS header-differential checks completed ({len(payloads)} payloads)", evidence="\n".join(evidence[:50]))
