from __future__ import annotations

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class AdvancedHTTPModule(ExploitModule):
    name = "Advanced HTTP / Desync"
    category = "http"

    async def run(self, ctx):
        payloads = get_payloads(self.name)
        rows = ctx.artifacts.get("recon.requests", []) or []
        evidence = []
        findings = 0
        for payload in payloads:
            ctx.logger(f"[payload] Advanced HTTP / Desync: {payload}")
            signal_rows = []
            for row in rows[:100]:
                if not isinstance(row, dict):
                    continue
                headers = {str(k).lower(): str(v) for k, v in (row.get("headers") or {}).items()}
                if payload == "CL.TE" and "content-length" in headers and "transfer-encoding" in headers:
                    signal_rows.append(row)
                if payload == "TE.CL" and "transfer-encoding" in headers and "content-length" in headers:
                    signal_rows.append(row)
                if payload == "HTTP/2 -> HTTP/1.1" and headers.get("te"):
                    signal_rows.append(row)
            status = "finding" if signal_rows else "tested"
            ctx.mark_payload(self.name, payload, status,
                             "captured request has desync-relevant headers; manual confirmation required" if signal_rows else "no passive signal")
            if signal_rows:
                findings += 1
                for row in signal_rows[:3]:
                    endpoint = str(row.get("url") or ctx.target.url)
                    ctx.add_finding(endpoint, payload, self.name,
                                    "Captured request contains a desync-relevant header combination; manual confirmation required",
                                    confidence="low")
                    evidence.append(f"{endpoint} -> {payload}; manual confirmation required")
            else:
                evidence.append(f"{payload} -> no passive signal")
        return ExploitResult(self.name, "signal" if findings else "no-signal", "Advanced HTTP checks completed without active desync payload injection", evidence="\n".join(evidence[:50]))
