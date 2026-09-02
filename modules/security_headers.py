from __future__ import annotations

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class SecurityHeadersModule(ExploitModule):
    name = "Security Headers"
    category = "hardening"

    async def run(self, ctx):
        payloads = get_payloads(self.name)
        requests = ctx.artifacts.get("recon.requests", []) or []
        endpoints = [r.get("url") for r in requests if isinstance(r, dict) and r.get("url")]
        if not endpoints:
            endpoints = [ctx.session.current_url or ctx.target.url]
        evidence = []
        findings = 0
        for endpoint in list(dict.fromkeys(endpoints))[:30]:
            try:
                original = ctx.original_request_for("GET", endpoint)
                r = await ctx.request_original(original, url=endpoint, method=original.get("method") or "GET")
            except Exception as exc:
                evidence.append(f"{endpoint} -> error: {exc}")
                continue
            headers = {str(k).lower(): str(v) for k, v in r.headers.items()}
            for idx, header_name in enumerate(payloads, 1):
                present = header_name.lower() in headers
                ctx.mark_payload(self.name, header_name, "tested", f"present={present}")
                ctx.logger(f"[payload {idx}/{len(payloads)}] Security Headers: {header_name}")
                evidence.append(f"{endpoint} [{header_name}] -> {'present' if present else 'missing'}")
                # Missing defensive headers are reported as hardening findings,
                # but never interrupt the remaining header checks.
                if not present:
                    # Missing defensive headers are hardening observations, not
                    # confirmed exploits. Keep them out of Vulnerability Findings.
                    ctx.artifacts.set("security_headers.missing", True)
        status = "no-signal"
        return ExploitResult(self.name, status, f"Security-header checks completed ({len(payloads)} payloads)", evidence="\n".join(evidence[:50]))
