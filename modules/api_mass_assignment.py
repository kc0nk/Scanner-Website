from __future__ import annotations

import json
from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class APIMassAssignmentModule(ExploitModule):
    name = "API / Mass Assignment"
    category = "api"

    async def run(self, ctx):
        payloads = get_payloads(self.name)
        rows = [r for r in (ctx.artifacts.get("recon.requests", []) or [])
                if isinstance(r, dict) and str(r.get("method", "GET")).upper() in {"POST", "PUT", "PATCH"}]
        evidence = []
        findings = 0
        for payload in payloads:
            candidates = []
            for row in rows[:80]:
                body = str(row.get("body", row.get("post_data", "")) or "")
                ctype = " ".join(str(v) for v in (row.get("headers") or {}).values()).lower()
                if "application/json" in ctype or body.strip().startswith(("{", "[")):
                    candidates.append(row)
            # Do not mutate live state automatically; surface the exact original
            # request as a manual confirmation candidate instead.
            state = "finding" if candidates else "not-applicable"
            ctx.mark_payload(self.name, payload, state,
                             "JSON write surface found; mutation is manual-only" if candidates else "no JSON write surface")
            evidence.append(f"{payload} -> candidates={len(candidates)}")
            if candidates:
                findings += 1
                endpoint = str(candidates[0].get("url") or ctx.target.url)
                ctx.add_finding(endpoint, payload, self.name,
                                "Potential mass-assignment surface; payload mutation intentionally requires manual confirmation",
                                confidence="low")
        return ExploitResult(self.name, "signal" if findings else "no-signal", "Mass-assignment surface checks completed (state-changing mutations not auto-executed)", evidence="\n".join(evidence[:50]))
