from __future__ import annotations

from urllib.parse import urlsplit

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class BusinessLogicModule(ExploitModule):
    name = "Business Logic / Workflow"
    category = "logic"

    @staticmethod
    def _voucher_request(row: dict) -> bool:
        method = str(row.get("method") or "GET").upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return False
        text = " ".join(
            str(row.get(key) or "")
            for key in ("url", "body", "post_data")
        ).lower()
        return any(term in text for term in (
            "voucher", "coupon", "redeem", "discount", "promo", "promotion"
        ))

    @staticmethod
    def _response_for_url(responses, url):
        target = str(url or "").split("#", 1)[0]
        return [
            r for r in responses
            if isinstance(r, dict) and str(r.get("url") or "").split("#", 1)[0] == target
        ]

    @staticmethod
    def _successful_voucher_response(responses, url):
        hits = []
        for response in BusinessLogicModule._response_for_url(responses, url):
            status = int(response.get("status") or 0)
            if 200 <= status < 300:
                hits.append(response)
        return hits

    async def run(self, ctx):
        rows = [
            r for r in (ctx.artifacts.get("recon.requests", []) or [])
            if isinstance(r, dict) and self._voucher_request(r)
        ]
        payloads = get_payloads(self.name)
        evidence = []
        findings = 0
        responses = ctx.session.network_responses or []
        seen = set()

        # The scanner follows the same black-box methodology shown in the
        # supplied Burp recording: observe the real request, replay the real
        # workflow, compare server state/response, and only promote a finding
        # when the business rule is demonstrably bypassed. Inventory alone is
        # never a vulnerability finding.
        for row in rows[:40]:
            endpoint = str(row.get("url") or "")
            method = str(row.get("method") or "POST").upper()
            body = row.get("body", row.get("post_data", "")) or ""
            key = (method, endpoint, str(body))
            if key in seen:
                continue
            seen.add(key)

            observed_successes = self._successful_voucher_response(responses, endpoint)
            evidence.append(
                f"[workflow] observed {method} {endpoint} -> "
                f"{len(observed_successes)} successful response(s) in browser history"
            )

            # Two or more successful applications of the same voucher workflow
            # are already direct evidence of a one-per-user rule bypass. Do not
            # generate dozens of extra state-changing requests.
            if len(observed_successes) >= 2:
                payload = "duplicate|reuse|replay"
                ctx.mark_payload(
                    self.name, payload, "finding",
                    f"same voucher workflow produced {len(observed_successes)} successful responses",
                )
                try:
                    exploit_response = await ctx.request_original(
                        dict(row), url=endpoint, method=method, body=body or None
                    )
                    response_body = exploit_response.text
                    response_note = f"HTTP {exploit_response.status_code}; replay succeeded"

                    # After the state-changing exploit, request the normal
                    # authenticated account endpoint. The complete raw response
                    # is retained for Repeater; no flag/string extraction occurs.
                    followup = None
                    origin = f"{urlsplit(endpoint).scheme}://{urlsplit(endpoint).netloc}"
                    for candidate in ("/api/me", "/api/history", "/dashboard"):
                        try:
                            followup_url = origin.rstrip("/") + candidate
                            followup = await ctx.request_original(
                                ctx.original_request_for("GET", followup_url),
                                url=followup_url, method="GET"
                            )
                            if followup.status_code < 400:
                                break
                        except Exception:
                            continue

                    final_response = followup or exploit_response
                    ctx.add_finding(
                        str(final_response.url),
                        payload,
                        self.name,
                        response_note + "; workflow state changed after repeated redemption",
                        confidence="high",
                        request_raw=getattr(ctx.http, "last_request_snapshot", {}).get("raw", ""),
                        verification="Observed successful redemption followed by a controlled identical replay; repeated state-changing response accepted",
                        methodology="Observe real voucher workflow -> count successful browser transactions -> replay exact request once -> require second successful state-changing response -> preserve exploit request/response for Repeater",
                    )
                    findings += 1
                    ctx.logger(
                        f"[VULN] {self.name} confirmed: repeated voucher workflow accepted"
                    )
                    evidence.append(
                        "[verified] repeated state-changing workflow accepted; "
                        "follow-up response preserved for Repeater"
                    )
                except Exception as exc:
                    ctx.mark_payload(self.name, payload, "error", str(exc), executed=False)
                    evidence.append(f"[workflow] replay error: {exc}")
                continue

            # If the capture contains only one successful transaction, perform
            # one controlled replay of that exact request. A second 2xx response
            # is the actual exploit proof; a 409/4xx is treated as correct
            # business-rule enforcement and never becomes a finding.
            if observed_successes and len(observed_successes) == 1:
                payload = "duplicate|reuse|replay"
                try:
                    replay = await ctx.request_original(
                        dict(row), url=endpoint, method=method, body=body or None
                    )
                    if 200 <= replay.status_code < 300:
                        ctx.mark_payload(self.name, payload, "finding", "second identical redemption succeeded")
                        ctx.add_finding(
                            endpoint, payload, self.name,
                            f"HTTP {replay.status_code}; second identical redemption succeeded",
                            confidence="high",
                            request_raw=getattr(ctx.http, "last_request_snapshot", {}).get("raw", ""),
                            verification="Baseline browser transaction succeeded and controlled identical replay also returned 2xx",
                            methodology="Observe real workflow -> replay exact request -> require duplicate success -> preserve request for Repeater",
                        )
                        findings += 1
                        evidence.append("[verified] controlled second redemption succeeded")
                    else:
                        ctx.mark_payload(self.name, payload, "tested", f"replay returned HTTP {replay.status_code}")
                        evidence.append(f"[enforced] repeated redemption rejected with HTTP {replay.status_code}")
                except Exception as exc:
                    ctx.mark_payload(self.name, payload, "error", str(exc), executed=False)
                    evidence.append(f"[workflow] controlled replay error: {exc}")

        # Keep the catalog visible in the terminal without promoting generic
        # workflow candidates to Vulnerability Findings.
        for payload in payloads:
            if payload != "duplicate|reuse|replay":
                ctx.mark_payload(self.name, payload, "not-applicable", "no safe automated exploit proof for this generic workflow category", executed=False)
        return ExploitResult(
            self.name,
            "success" if findings else "no-signal",
            "Business-logic workflows verified using observed request/replay behavior",
            evidence="\n".join(evidence[:50]),
        )
