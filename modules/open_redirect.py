from __future__ import annotations
from urllib.parse import parse_qsl,urlsplit,urlencode,urlunsplit
from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads
class OpenRedirectModule(ExploitModule):
    name="Open Redirect"; category="redirect"
    PARAMS={"next","url","redirect","redirect_url","return","return_to","dest","destination"}
    async def run(self,ctx):
        evidence=[]; probes=get_payloads(self.name)
        for endpoint in ctx.artifacts.get("recon.endpoints",[])[:60]:
            p=urlsplit(endpoint); params=parse_qsl(p.query,keep_blank_values=True)
            for idx,(name,_) in enumerate(params):
                if name.lower() not in self.PARAMS: continue
                for i,payload in enumerate(probes,1):
                    ctx.logger(f"[payload {i}/{len(probes)}] Open Redirect: {payload}")
                    m=params.copy();m[idx]=(name,payload);probe=urlunsplit((p.scheme,p.netloc,p.path,urlencode(m),p.fragment))
                    try:
                        r=await ctx.http.request("GET",probe,follow_redirects=False)
                        evidence.append(f"{probe} -> {r.status_code} location={r.headers.get('location','')}")
                        location = r.headers.get("location","")
                        if location.startswith(("http://example.com","https://example.com","//example.com")):
                            ctx.artifacts.set("open_redirect.hit",probe)
                            ctx.add_finding(probe, payload, self.name, f"HTTP {r.status_code}; Location: {location}", confidence="high")
                    except Exception as exc:evidence.append(str(exc))
        return ExploitResult(self.name,"signal" if ctx.artifacts.get("open_redirect.hit") else "no-signal","Open redirect probes completed",evidence="\n".join(evidence[:20]))
