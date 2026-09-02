from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class XSSModule(ExploitModule):
    name = "XSS"
    category = "client"

    async def run(self, ctx):
        request_rows = ctx.artifacts.get("recon.requests", []) or []
        endpoints = ctx.artifacts.get("recon.endpoints", [])
        if not request_rows:
            request_rows = [{"method":"GET","url":u,"headers":{},"body":""} for u in endpoints]
        token = "ctf-xss-probe"
        evidence = []
        payloads = get_payloads(self.name)
        payload_counter = 0
        for request in request_rows[:80]:
            endpoint = str(request.get("url") or "")
            method = str(request.get("method") or "GET").upper()
            req_headers = dict(request.get("headers") or {})
            parts = urlsplit(endpoint)
            params = parse_qsl(parts.query, keep_blank_values=True)
            for idx, (name, _) in enumerate(params[:8]):
                for payload in payloads:
                    payload_counter += 1
                    ctx.logger(f"[payload {payload_counter}/{len(payloads)}] XSS: {payload}")
                    mutated = params.copy()
                    mutated[idx] = (name, payload)
                    probe = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))
                    try:
                        original = dict(request)
                        resp = await ctx.request_original(original, url=probe, method=method, headers=req_headers, body=request.get("body") or None)
                        ctx.inspect_source(str(resp.url), resp.text, payload, payload_counter, resp.headers.get("content-type", ""))
                        if token in resp.text:
                            msg = f"Reflected input detected in {name} at {parts.path} using {payload}"
                            evidence.append(msg)
                            ctx.add_finding(probe, payload, self.name, f"HTTP {resp.status_code}; reflected marker observed", confidence="high")
                    except Exception as exc:
                        evidence.append(str(exc))
        return ExploitResult(self.name, "signal" if evidence else "no-signal", "Reflection probes completed", evidence="\n".join(evidence[:20]))
