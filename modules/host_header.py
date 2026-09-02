from __future__ import annotations

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class HostHeaderModule(ExploitModule):
    name = "Host Header / Reverse Proxy"
    category = "http"

    async def run(self, ctx):
        payloads = get_payloads(self.name)
        rows = ctx.artifacts.get("recon.requests", []) or []
        rows = rows[:30] or [{"method": "GET", "url": ctx.target.url, "headers": {}, "body": ""}]
        evidence = []
        findings = 0
        for row in rows:
            endpoint = str(row.get("url") or "")
            method = str(row.get("method") or "GET").upper()
            for idx, payload in enumerate(payloads, 1):
                try:
                    key, value = payload.split(":", 1)
                    headers = {key.strip(): value.strip()}
                    original = dict(row)
                    resp = await ctx.request_original(original, url=endpoint, method=method, headers=headers,
                                                       body=row.get("body") or None)
                    location = resp.headers.get("location", "")
                    marker = value.strip()
                    signal = marker in location or marker in (resp.text or "")
                    ctx.mark_payload(self.name, payload, "finding" if signal else "tested", f"HTTP {resp.status_code}")
                    evidence.append(f"{endpoint} [{key}] -> {resp.status_code}; reflection={signal}")
                    if signal:
                        findings += 1
                        ctx.add_finding(endpoint, payload, self.name,
                                        f"HTTP {resp.status_code}; supplied host/proxy header reflected in response",
                                        confidence="medium")
                except Exception as exc:
                    ctx.mark_payload(self.name, payload, "error", str(exc))
                    evidence.append(f"{endpoint} -> error: {exc}")
        return ExploitResult(self.name, "signal" if findings else "no-signal", "Host-header probes completed (all payloads tested)", evidence="\n".join(evidence[:50]))
