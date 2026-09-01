from __future__ import annotations

from urllib.parse import urlencode

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class CSRFModule(ExploitModule):
    name = "CSRF"
    category = "access"

    @staticmethod
    def _state_changing(method: str, action: str) -> bool:
        return method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and bool(action)

    async def run(self, ctx):
        evidence = []
        forms = ctx.artifacts.get("recon.forms", []) or []
        probes = get_payloads(self.name)
        tested = 0
        for form in forms[:30]:
            method = str(form.get("method", "GET")).upper()
            action = form.get("action") or ctx.target.url
            if not self._state_changing(method, action):
                continue
            inputs = form.get("inputs", []) or []
            fields = [(str(x.get("name")), str(x.get("value", ""))) for x in inputs if x.get("name")]
            token_fields = [name for name, _ in fields if any(k in name.lower() for k in ("csrf", "xsrf", "token", "nonce"))]
            base_data = dict(fields)
            try:
                baseline = await ctx.http.request(method, action, headers={"Content-Type": "application/x-www-form-urlencoded"}, content=urlencode(base_data), follow_redirects=False)
            except Exception as exc:
                evidence.append(f"baseline {action}: {exc}")
                continue
            for probe in probes:
                tested += 1
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                if probe.startswith("Origin:") or probe.startswith("Referer:"):
                    key, value = probe.split(":", 1)
                    headers[key.strip()] = value.strip()
                elif probe == "Origin: null":
                    headers["Origin"] = "null"
                elif probe.startswith("Content-Type:"):
                    headers["Content-Type"] = probe.split(":", 1)[1].strip()
                data = dict(base_data)
                # A CSRF check becomes meaningful when a synchronizer token is removed.
                if token_fields:
                    for name in token_fields:
                        data.pop(name, None)
                try:
                    test = await ctx.http.request(method, action, headers=headers, content=urlencode(data), follow_redirects=False)
                    evidence.append(f"{action} [{probe}] -> {test.status_code}, {len(test.text)} bytes")
                    same_status = test.status_code == baseline.status_code
                    small_delta = abs(len(test.text) - len(baseline.text)) <= max(80, int(len(baseline.text) * 0.10))
                    accepted = same_status and small_delta
                    if accepted and not token_fields:
                        ctx.add_finding(action, probe, self.name, f"HTTP {test.status_code}; state-changing form accepted without visible CSRF token", confidence="medium")
                        return ExploitResult(self.name, "signal", "Potential CSRF: state-changing form accepts cross-origin-style request", evidence="\n".join(evidence[-10:]))
                    if accepted and token_fields and "Origin" in headers:
                        ctx.add_finding(action, probe, self.name, f"HTTP {test.status_code}; response remained equivalent after removing token under {headers['Origin']}", confidence="medium")
                        return ExploitResult(self.name, "signal", "Potential CSRF: token/origin protection may be ineffective", evidence="\n".join(evidence[-10:]))
                except Exception as exc:
                    evidence.append(f"{action} [{probe}] -> {exc}")
        return ExploitResult(self.name, "no-signal", f"CSRF probes completed ({tested} tested)", evidence="\n".join(evidence[:30]))
