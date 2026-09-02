from __future__ import annotations

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class BusinessLogicModule(ExploitModule):
    name = "Business Logic / Workflow"
    category = "logic"

    async def run(self, ctx):
        payloads = get_payloads(self.name)
        rows = ctx.artifacts.get("recon.requests", []) or []
        evidence = []
        findings = 0
        for payload in payloads:
            matches = []
            for row in rows[:200]:
                if not isinstance(row, dict):
                    continue
                text = (str(row.get("url") or "") + " " + str(row.get("body", row.get("post_data", "")) or "")).lower()
                if any(term in text for term in payload.lower().split("|")):
                    matches.append(row)
            ctx.mark_payload(self.name, payload, "finding" if matches else "tested",
                             "workflow candidate discovered; no state-changing replay performed" if matches else "no matching workflow surface")
            evidence.append(f"{payload} -> candidates={len(matches)}")
            if matches:
                findings += 1
                row = matches[0]
                endpoint = str(row.get("url") or ctx.target.url)
                ctx.add_finding(endpoint, payload, self.name,
                                "Potential business-logic workflow surface discovered; manual/state-aware confirmation required",
                                confidence="low")
        return ExploitResult(self.name, "signal" if findings else "no-signal", "Business-logic inventory completed without duplicating state-changing transactions", evidence="\n".join(evidence[:50]))
