from __future__ import annotations
from core.module import ExploitModule
from core.models import Artifact, ExploitResult

class HTTPMethodsModule(ExploitModule):
    name="HTTP Method Discovery"; category="recon"
    async def run(self,ctx):
        requests=ctx.artifacts.get("recon.requests",[]) or []
        forms=ctx.artifacts.get("recon.forms",[]) or []
        observed=sorted({str(r.get("method") or "GET").upper() for r in requests if r.get("method")})
        declared=sorted({str(f.get("method") or "GET").upper() for f in forms if f.get("method")})
        methods=sorted(set(observed)|set(declared)|{"GET"})
        evidence=[f"Observed methods: {', '.join(observed) if observed else 'GET'}"]
        if declared: evidence.append(f"Form-declared methods: {', '.join(declared)}")
        checked=0
        candidates=[]
        candidates += [r.get("url") for r in requests]
        candidates += [f.get("action") for f in forms]
        for endpoint in list(dict.fromkeys(candidates))[:25]:
            if not endpoint or not ctx.in_scope(endpoint): continue
            try:
                r=await ctx.http.request("OPTIONS",endpoint,follow_redirects=False)
                allow=r.headers.get("allow","")
                evidence.append(f"OPTIONS {endpoint} -> {r.status_code}; Allow={allow or '-'}")
                checked += 1
                if allow: methods.extend(x.strip().upper() for x in allow.split(",") if x.strip())
            except Exception as exc:
                evidence.append(f"OPTIONS {endpoint} -> error: {exc}")
        methods=sorted(set(methods)); ctx.artifacts.set("recon.methods",methods); ctx.artifacts.set("recon.options_checked",checked)
        return ExploitResult(self.name,"signal" if len(methods)>1 else "no-signal",f"HTTP methods mapped: {', '.join(methods)}",[Artifact("recon.methods",methods,self.name)],"\n".join(evidence[:30]))
