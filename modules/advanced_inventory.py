from __future__ import annotations

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class AdvancedInventoryModule(ExploitModule):
    name = "Advanced Injection / OAuth / Race / Deserialization"
    category = "advanced"

    async def run(self, ctx):
        packs = ["OAuth / OIDC", "Race Condition", "Deserialization", "LDAP / XPath / XML Injection"]
        rows = ctx.artifacts.get("recon.requests", []) or []
        evidence = []
        findings = 0
        haystack = "\n".join(
            str(r.get("url", "")) + " " + str(r.get("body", r.get("post_data", "")) or "")
            for r in rows if isinstance(r, dict)
        ).lower()
        for pack in packs:
            for payload in get_payloads(pack):
                low = payload.lower()
                signal = False
                if pack == "OAuth / OIDC":
                    signal = any(x in haystack for x in ("oauth", "openid", "authorize", "redirect_uri", "response_type"))
                elif pack == "Race Condition":
                    signal = any(x in haystack for x in ("redeem", "coupon", "reset", "transaction", "checkout"))
                elif pack == "Deserialization":
                    signal = any(x in haystack for x in ("serialize", "deserialize", "pickle", "yaml", "object"))
                else:
                    signal = any(x in haystack for x in ("ldap", "xpath", "xml", "filter"))
                ctx.mark_payload(self.name, f"{pack}: {payload}", "not-applicable" if not signal else "tested",
                                 "surface discovered; manual payload confirmation required" if signal else "no matching surface")
                evidence.append(f"{pack} / {payload} -> {'manual-confirmation' if signal else 'not-applicable'}")
                # Inventory/manual-confirmation signals are deliberately not
                # promoted into Vulnerability Findings.

        return ExploitResult(self.name, "signal" if findings else "no-signal", "Advanced technique inventory completed", evidence="\n".join(evidence[:80]))
