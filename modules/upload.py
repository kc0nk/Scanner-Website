from __future__ import annotations
from pathlib import Path
from urllib.parse import urljoin
from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads

class FileUploadModule(ExploitModule):
    name = "File Upload"
    category = "upload"
    async def run(self,ctx):
        forms=[f for f in (ctx.artifacts.get("recon.forms",[]) or []) if f.get("method")=="POST"]
        evidence=[]
        for form in forms[:15]:
            action=form.get("action") or ctx.target.url
            if not any(str(x.get("type","")).lower()=="file" for x in form.get("inputs",[])):
                continue
            for i,filename in enumerate(get_payloads(self.name),1):
                ctx.logger(f"[payload {i}/{len(get_payloads(self.name))}] File Upload: {filename}")
                try:
                    body=b"CTF-Workbench upload probe v3\n"
                    # Raw multipart support is intentionally delegated to httpx only for this module.
                    resp=await ctx.http.request("POST",action,headers={"Content-Type":"application/octet-stream","X-Filename":filename},content=body,use_curl=False)
                    ctx.inspect_source(str(resp.url),resp.text,filename,i,resp.headers.get("content-type",""))
                    evidence.append(f"{action} [{filename}] -> {resp.status_code}, {len(resp.text)} bytes")
                    low = resp.text.lower()
                    if resp.status_code in (200,201,202,204) and filename.lower().endswith((".php;.jpg", ".jpg.php", ".php%00.jpg")):
                        ctx.add_finding(action, filename, self.name, f"HTTP {resp.status_code}; suspicious upload filename accepted", confidence="medium")
                        evidence.append(f"[finding] {action} [{filename}] -> suspicious upload accepted; continuing remaining upload probes")
                except Exception as exc:evidence.append(str(exc))
        return ExploitResult(self.name,"signal" if evidence else "no-signal","File upload probes completed",evidence="\n".join(evidence[:20]))
