from __future__ import annotations

import json
from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class GraphQLModule(ExploitModule):
    name = "GraphQL"
    category = "api"

    async def run(self, ctx):
        payloads = get_payloads(self.name)
        requests = ctx.artifacts.get("recon.requests", []) or []
        candidates = []
        for row in requests:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url") or "")
            body = str(row.get("body", row.get("post_data", "")) or "")
            ctype = " ".join(f"{k}:{v}" for k, v in (row.get("headers") or {}).items()).lower()
            if "/graphql" in url.lower() or "graphql" in body.lower() or "application/graphql" in ctype:
                candidates.append(row)
        if not candidates:
            base = ctx.session.current_url or ctx.target.url
            candidates = [{"method": "GET", "url": base, "headers": {}, "body": ""}]
        evidence = []
        findings = 0
        for row in list(candidates)[:20]:
            endpoint = str(row.get("url") or "")
            method = str(row.get("method") or "GET").upper()
            for idx, payload in enumerate(payloads, 1):
                ctx.logger(f"[payload {idx}/{len(payloads)}] GraphQL: {payload}")
                try:
                    original = dict(row)
                    if method == "POST":
                        body = row.get("body", row.get("post_data", "")) or ""
                        if "__typename" in payload:
                            mutated = body if body else json.dumps({"query": "{__typename}"})
                        else:
                            mutated = json.dumps({"query": payload})
                        resp = await ctx.request_original(original, url=endpoint, method=method,
                                                           headers={"Content-Type": "application/json"}, body=mutated)
                    else:
                        resp = await ctx.request_original(original, url=endpoint, method=method)
                    text = resp.text or ""
                    signal = "__schema" in text or "__typename" in text or '"data"' in text and '"errors"' in text
                    ctx.mark_payload(self.name, payload, "finding" if signal else "tested", f"HTTP {resp.status_code}")
                    evidence.append(f"{endpoint} -> {resp.status_code}; graphql_signal={signal}")
                    if signal:
                        findings += 1
                        ctx.add_finding(endpoint, payload, self.name,
                                        f"HTTP {resp.status_code}; GraphQL response/introspection signal observed",
                                        confidence="medium")
                except Exception as exc:
                    ctx.mark_payload(self.name, payload, "error", str(exc))
                    evidence.append(f"{endpoint} -> error: {exc}")
        status = "signal" if findings else "no-signal"
        return ExploitResult(self.name, status, "GraphQL probes completed (all payloads tested)", evidence="\n".join(evidence[:50]))
