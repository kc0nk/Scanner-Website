from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class SQLiModule(ExploitModule):
    name = "SQL Injection"
    category = "injection"

    async def run(self, ctx):
        base = ctx.target.url
        candidates = []
        for item in ctx.artifacts.get("recon.requests", []) or []:
            if item.get("url"):
                candidates.append((str(item.get("method") or "GET").upper(), str(item.get("url")), dict(item.get("headers") or {}), item.get("body") or None))
        try:
            text, final_url, _ = await ctx.get_text("/")
            candidates.extend(("GET", u, {}, None) for u in ctx.discover_links(final_url, text))
        except Exception:
            pass
        candidates.append(("GET", base, {}, None))
        seen = set()
        evidence = []
        payloads = get_payloads(self.name)
        payload_counter = 0
        for method, candidate, req_headers, req_body in candidates:
            parts = urlsplit(candidate)
            params = parse_qsl(parts.query, keep_blank_values=True)
            if not params or (method, candidate) in seen:
                continue
            seen.add((method, candidate))
            for idx, (name, value) in enumerate(params[:5]):
                for payload in payloads:
                    payload_counter += 1
                    ctx.logger(f"[payload {payload_counter}/{len(payloads)}] SQL Injection: {payload}")
                    mutated = params.copy()
                    mutated[idx] = (name, value + payload)
                    probe = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))
                    try:
                        normal = await ctx.http.request(method, candidate, headers=req_headers, content=req_body)
                        test = await ctx.http.request(method, probe, headers=req_headers, content=req_body)
                        delta = len(test.text) - len(normal.text)
                        ctx.inspect_source(str(test.url), test.text, payload, payload_counter, test.headers.get("content-type", ""))
                        marker = any(x in test.text.lower() for x in ["sql syntax", "mysql", "sqlite", "postgresql", "odbc", "ora-"])
                        msg = f"Potential SQLi signal in {name} at {parts.path}: status {normal.status_code}->{test.status_code}, size delta {delta}"
                        if marker or abs(delta) > 300:
                            evidence.append(msg)
                            ctx.add_finding(probe, payload, self.name, f"HTTP {test.status_code}; size delta {delta}", confidence="medium")
                    except Exception as exc:
                        evidence.append(f"{probe}: {exc}")
        status = "signal" if evidence else "no-signal"
        return ExploitResult(self.name, status, "SQLi differential probes completed", evidence="\n".join(evidence[:20]))
