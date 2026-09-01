from __future__ import annotations
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads

class SSRFModule(ExploitModule):
    name = "SSRF"
    category = "network"
    URL_NAMES = {"url", "uri", "link", "dest", "destination", "target", "redirect", "next", "fetch", "callback", "image"}

    async def run(self, ctx):
        evidence=[]
        payloads=get_payloads(self.name)
        for endpoint in ctx.artifacts.get("recon.endpoints", [])[:60]:
            p=urlsplit(endpoint); params=parse_qsl(p.query, keep_blank_values=True)
            candidates=[(i,n) for i,(n,_) in enumerate(params) if n.lower() in self.URL_NAMES] or list(enumerate([n for n,_ in params]))[:3]
            for idx,name in candidates:
                for n,payload in enumerate(payloads,1):
                    ctx.logger(f"[payload {n}/{len(payloads)}] SSRF: {payload}")
                    mutated=params.copy(); mutated[idx]=(name,payload)
                    probe=urlunsplit((p.scheme,p.netloc,p.path,urlencode(mutated),p.fragment))
                    try:
                        r=await ctx.http.request("GET",probe)
                        ctx.inspect_source(str(r.url),r.text,payload,n,r.headers.get("content-type",""))
                        evidence.append(f"{probe} -> {r.status_code}, {len(r.text)} bytes")
                    except Exception as exc: evidence.append(str(exc))
        return ExploitResult(self.name,"signal" if ctx.artifacts.get("ssrf.hit") else "no-signal","SSRF probes completed",evidence="\n".join(evidence[:20]))
