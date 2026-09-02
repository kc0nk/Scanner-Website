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
                            # Reflection alone is not promoted. For active canaries,
                            # render the exact probe URL in the persistent browser and
                            # verify DOM execution. Non-executing reflection remains a
                            # tested candidate only.
                            executed = False
                            if "data-ctf-xss" in payload:
                                try:
                                    await ctx.http._ensure_browser()
                                    page = ctx.http._browser_page
                                    await page.goto(probe, wait_until="domcontentloaded", timeout=10000)
                                    executed = await page.evaluate("document.documentElement.getAttribute('data-ctf-xss') === '1'")
                                except Exception as browser_exc:
                                    evidence.append(f"[xss-browser] {probe}: {browser_exc}")
                            if executed:
                                msg = f"[VERIFIED] XSS execution in {name} at {parts.path} using {payload}"
                                evidence.append(msg)
                                ctx.mark_payload(self.name, payload, "finding", f"DOM execution marker confirmed for parameter={name}")
                                ctx.add_finding(
                                    probe, payload, self.name,
                                    f"HTTP {resp.status_code}; reflected and executed in browser; parameter={name}",
                                    confidence="high",
                                    parameter=name,
                                    verification="Payload reflected into response and browser DOM execution marker data-ctf-xss=1 was observed",
                                    methodology="Observe request -> inject XSS canary -> verify reflection -> render exact probe URL in browser -> verify JavaScript execution -> preserve exploit request for Repeater",
                                )
                            else:
                                ctx.mark_payload(self.name, payload, "tested", f"reflected but execution not verified; parameter={name}")
                                evidence.append(f"[candidate] reflected XSS marker in {name}; execution not promoted")
                    except Exception as exc:
                        evidence.append(str(exc))
        return ExploitResult(self.name, "signal" if evidence else "no-signal", "Reflection probes completed", evidence="\n".join(evidence[:20]))
