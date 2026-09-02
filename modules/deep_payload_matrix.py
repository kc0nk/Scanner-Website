from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class DeepPayloadMatrixModule(ExploitModule):
    """Execute the remaining public-methodology payload families on observed input surfaces.

    This is deliberately evidence-driven: a payload is not a finding merely because
    the response changed. Only a technique-specific marker/reflection/parse error is
    promoted, and every executed payload is recorded in the coverage ledger.
    """

    name = "Deep Payload Matrix / CTF Techniques"
    category = "advanced"

    FAMILIES = {
        "LDAP / XPath / XML Injection": ("ldap", "xpath", "xml", "filter", "search", "query"),
        "Prototype Pollution": ("json", "config", "options", "merge", "proto"),
        "NoSQL Injection": ("search", "filter", "query", "user", "login"),
        "SSTI": ("template", "render", "name", "title", "message", "query"),
        "LFI / Path Traversal": ("file", "path", "page", "template", "include", "download"),
        "SSRF": ("url", "uri", "callback", "webhook", "fetch", "image", "link", "redirect"),
        "Open Redirect": ("url", "next", "redirect", "return", "continue", "dest"),
        "XSS": ("q", "query", "search", "name", "title", "message", "comment", "input"),
    }

    @staticmethod
    def _marker(family: str, payload: str, text: str) -> bool:
        low = (text or "").lower()
        if family == "XSS":
            return "ctf-xss-probe" in low or "<x-ctf" in low
        if family == "SSTI":
            return bool(re.search(r"\b49\b", low)) or "potential expression" in low
        if family == "LFI / Path Traversal":
            return any(x in low for x in ("root:x:", "127.0.0.1", "localhost", "[extensions]", "linux version"))
        if family == "SSRF":
            return any(x in low for x in ("ami-id", "instance-id", "metadata", "localhost", "127.0.0.1"))
        if family == "LDAP / XPath / XML Injection":
            return any(x in low for x in ("ldap", "xpath", "xml parse", "entity", "syntax error"))
        if family == "NoSQL Injection":
            return any(x in low for x in ("mongodb", "bson", "mongoerror", "unknown operator", "query selector"))
        if family == "Prototype Pollution":
            return "polluted" in low and "true" in low
        if family == "Open Redirect":
            return "example.com" in low and any(x in low for x in ("location", "redirect", "refresh"))
        return False

    async def run(self, ctx):
        rows = [r for r in (ctx.artifacts.get("recon.requests", []) or []) if isinstance(r, dict) and r.get("url")]
        evidence = []
        verified = 0
        total = 0
        if not rows:
            return ExploitResult(self.name, "no-signal", "No observed request surfaces for deep payload execution")

        for family, keywords in self.FAMILIES.items():
            payloads = get_payloads(family)
            for row in rows[:40]:
                endpoint = str(row.get("url") or "")
                method = str(row.get("method") or "GET").upper()
                parts = urlsplit(endpoint)
                params = parse_qsl(parts.query, keep_blank_values=True)
                body = str(row.get("body", row.get("post_data", "")) or "")
                names = [name for name, _ in params if any(k in name.lower() for k in keywords)]
                if not names and body:
                    names = ["__body__"]
                if not names:
                    continue
                for name in names[:4]:
                    for idx, payload in enumerate(payloads, 1):
                        total += 1
                        ctx.logger(f"[payload {total}] {family}: {payload}")
                        try:
                            original = dict(row)
                            if name == "__body__":
                                mutated_body = body + ("&" if body else "") + "probe=" + payload
                                resp = await ctx.request_original(original, url=endpoint, method=method, body=mutated_body or None)
                                probe_url = endpoint
                            else:
                                mutated = params.copy()
                                pos = next(i for i, pair in enumerate(mutated) if pair[0] == name)
                                mutated[pos] = (name, payload)
                                probe_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))
                                resp = await ctx.request_original(original, url=probe_url, method=method, body=body or None)
                            hit = self._marker(family, payload, resp.text)
                            ctx.mark_payload(self.name, f"{family}: {payload}", "finding" if hit else "tested", f"HTTP {resp.status_code}; marker={hit}")
                            if hit:
                                verified += 1
                                detail = f"HTTP {resp.status_code}; technique-specific exploit marker observed; parameter={name}; payload={payload}"
                                ctx.add_finding(
                                    probe_url,
                                    payload,
                                    family,
                                    detail,
                                    confidence="high",
                                    terminal_ready=False,
                                    request_raw=getattr(ctx.http, "last_request_snapshot", {}).get("raw", ""),
                                )
                                evidence.append(f"[VERIFIED] {family} | {method} {probe_url} | parameter={name} | payload={payload}")
                            else:
                                evidence.append(f"[tested] {family} | {method} {probe_url} | parameter={name} | payload={payload} -> HTTP {resp.status_code}")
                        except Exception as exc:
                            ctx.mark_payload(self.name, f"{family}: {payload}", "error", str(exc), executed=False)
                            evidence.append(f"[error] {family}: {exc}")
        return ExploitResult(
            self.name,
            "success" if verified else ("signal" if total else "no-signal"),
            f"Deep payload matrix completed: executed={total}, verified={verified}",
            evidence="\n".join(evidence[:120]),
        )
