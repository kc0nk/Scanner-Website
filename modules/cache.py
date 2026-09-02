from __future__ import annotations

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class CacheModule(ExploitModule):
    name = "Web Cache / Cache Key"
    category = "http"

    async def run(self, ctx):
        payloads = get_payloads(self.name)
        rows = ctx.artifacts.get("recon.requests", []) or []
        rows = [r for r in rows if isinstance(r, dict) and str(r.get("method", "GET")).upper() in {"GET", "HEAD"}][:30]
        rows = rows or [{"method": "GET", "url": ctx.target.url, "headers": {}, "body": ""}]
        evidence = []
        findings = 0
        for row in rows:
            endpoint = str(row.get("url") or "")
            original = dict(row)
            try:
                baseline = await ctx.request_original(original, url=endpoint, method=row.get("method") or "GET")
            except Exception as exc:
                evidence.append(f"{endpoint} -> baseline error: {exc}")
                continue
            for idx, payload in enumerate(payloads, 1):
                try:
                    key, value = payload.split(":", 1)
                    resp = await ctx.request_original(original, url=endpoint, method=row.get("method") or "GET",
                                                       headers={key.strip(): value.strip()})
                    cache = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
                    cache_signal = any(x in cache for x in ("cache-control", "age:", "x-cache", "cf-cache-status", "x-cache-status"))
                    reflected = value.strip() in (resp.text or "") or value.strip() in resp.headers.get("location", "")
                    signal = cache_signal and reflected
                    ctx.mark_payload(self.name, payload, "finding" if signal else "tested", f"cache_headers={cache_signal}; reflection={reflected}")
                    evidence.append(f"{endpoint} [{key}] -> {resp.status_code}; cache_headers={cache_signal}; reflection={reflected}")
                    if signal:
                        findings += 1
                        ctx.add_finding(endpoint, payload, self.name,
                                        f"HTTP {resp.status_code}; cache behavior and unkeyed-header reflection signal",
                                        confidence="low")
                except Exception as exc:
                    ctx.mark_payload(self.name, payload, "error", str(exc))
                    evidence.append(f"{endpoint} -> error: {exc}")
        return ExploitResult(self.name, "signal" if findings else "no-signal", "Cache probes completed (all payloads tested)", evidence="\n".join(evidence[:50]))
