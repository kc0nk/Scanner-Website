from __future__ import annotations

from core.context import ExploitContext
from core.models import Target, ExploitResult
from modules import ALL_MODULES
from core.payloads import payload_summary, total_payloads, writeup_payload_summary
from app.version import __version__


class ExploitEngine:
    """Run every implemented exploitation module in a single pass.

    The engine intentionally continues after a finding so one click exercises
    the complete currently implemented module set. Rate limits/block pages are
    handled by the HTTP client with bounded backoff; no IP rotation or control
    bypass is attempted.
    """

    def __init__(self, target: Target, session, logger, selected_modules=None):
        self.ctx = ExploitContext(target, session, logger)
        self.logger = logger
        self.selected_modules = list(selected_modules or ALL_MODULES)

    async def run(self):
        results = []
        total_modules = len(self.selected_modules)
        self.logger(f"[+] Workbench version: {__version__}")
        self.logger(f"[+] Browser current URL: {self.ctx.session.current_url or self.ctx.target.url}")
        self.logger(
            f"[+] Browser history: {len(self.ctx.session.navigation_history)} | "
            f"Requests: {len(self.ctx.session.network_requests)}"
        )
        self.logger(
            f"[+] One-click mode: {total_modules} implemented module(s), "
            f"{total_payloads()} payload(s) across {len(payload_summary())} payload packs"
        )
        writeup_total = sum(writeup_payload_summary().values())
        self.logger(f"[+] Write-up derived probes loaded: {writeup_total}")

        try:
            self.logger("[>] Preparing browser/session transport")
            try:
                await self.ctx.http.prime_browser_session()
                cookie_names = sorted(c.get("name", "") for c in self.ctx.session.cookies if c.get("name"))
                self.logger(f"[ok] Browser session ready; cookies={', '.join(cookie_names) or 'none'}")
            except Exception as exc:
                self.logger(f"[!] Browser session bootstrap warning: {exc}")
            self.logger("[>] Passive source/DOM inspection")
            self.ctx.inspect_source(self.ctx.session.current_url or self.ctx.target.url, self.ctx.session.page_html or "", payload="PASSIVE", payload_index=0, content_type="text/html")

            for index, cls in enumerate(self.selected_modules, start=1):
                module_name = getattr(cls, "name", cls.__name__)
                self.logger(f"[module {index}/{total_modules}] {module_name}")
                self.logger(f"[>] {module_name}")
                try:
                    result = await cls().run(self.ctx)
                except Exception as exc:
                    result = ExploitResult(module_name, "error", str(exc))

                results.append(result)
                self.logger(f"[{result.status}] {result.message}")
                if result.evidence:
                    for line in result.evidence.splitlines()[:8]:
                        self.logger("    " + line)

                # Continue through every implemented module after findings.
                if self.ctx.artifacts.get("http.rate_limited"):
                    self.logger("[!] Rate limit observed; remaining modules continue with bounded backoff.")

            findings = self.ctx.artifacts.get("findings.detected", []) or []
            self.logger(f"[+] All modules completed: {len(results)}/{total_modules}")
            self.logger(f"[+] Vulnerability findings: {len(findings)}")
            self.logger("[+] Vulnerability scan complete")
            return results, self.ctx.artifacts.all()
        finally:
            await self.ctx.close()
