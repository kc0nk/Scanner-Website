from __future__ import annotations

import asyncio

from core.context import ExploitContext
from core.models import Target, ExploitResult
from modules import ALL_MODULES
from core.payloads import payload_summary, total_payloads, writeup_payload_summary
from app.version import __version__


class ExploitEngine:
    """Run every selected vulnerability module to a terminal state.

    Findings are data only: they never control module/scan flow. The scanner
    does not extract, classify, print, or store challenge flags. Repeater gets
    the raw HTTP response and may display whatever the target returned.
    """

    def __init__(self, target: Target, session, logger, selected_modules=None):
        self.ctx = ExploitContext(target, session, logger)
        self.logger = logger
        self.selected_modules = list(selected_modules or ALL_MODULES)

    async def _run_module(self, cls, module_name, index, total_modules):
        """Run one module with a hard deadline and visible heartbeat.

        A finding is data, never a control-flow signal. The module task is
        allowed to finish all of its own probes; the heartbeat prevents long
        modules from looking frozen in the GUI.
        """
        task = asyncio.create_task(cls().run(self.ctx))
        deadline = asyncio.get_running_loop().time() + 180.0
        heartbeat = 0
        while not task.done():
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                raise asyncio.TimeoutError
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=min(10.0, remaining))
            except asyncio.TimeoutError:
                heartbeat += 1
                finding_count = len(self.ctx.artifacts.get("findings.detected", []) or [])
                elapsed = heartbeat * 10
                self.logger(
                    f"[heartbeat] {module_name} still running ({elapsed}s); "
                    f"findings={finding_count}; scanner continues"
                )
        return task.result()

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
            self.logger("[i] Module timeout: 180s each; a finding NEVER stops the scanner")
            self.logger("[i] Methodology: observe real request -> replay baseline -> mutate/replay -> verify response/state -> promote only confirmed exploit")
            self.logger("[i] Payload mode: FULL ORIGINAL REQUEST — captured method/headers/cookies/body are preserved for probes")
            self.logger("[i] Cleanup timeout: 5s; completion is reported even if browser cleanup stalls")
            try:
                await asyncio.wait_for(self.ctx.http.prime_browser_session(), timeout=20.0)
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
                started = asyncio.get_running_loop().time()
                try:
                    # Bound every module independently so one slow endpoint,
                    # redirect chain, or library call cannot make the whole
                    # scanner look frozen forever. Cancellation is propagated
                    # into the module and the shared HTTP/browser session is
                    # cleaned up by the engine's finally block.
                    result = await self._run_module(cls, module_name, index, total_modules)
                except asyncio.TimeoutError:
                    elapsed = asyncio.get_running_loop().time() - started
                    result = ExploitResult(module_name, "timeout", f"module timed out after {elapsed:.1f}s")
                except asyncio.CancelledError:
                    self.logger(f"[!] Scanner cancelled while running {module_name}")
                    raise
                except Exception as exc:
                    result = ExploitResult(module_name, "error", str(exc))

                # Reconcile the module ledger before advancing. This never turns a
                # finding into a stop condition; it only makes payload coverage auditable.
                module_coverage = self.ctx.finalize_payload_coverage(module_name)
                results.append(result)
                finding_count = len(self.ctx.artifacts.get("findings.detected", []) or [])
                self.logger(f"[{result.status}] {result.message}")
                if finding_count:
                    self.logger(f"[finding] {finding_count} finding(s) recorded; continuing to module {index + 1}/{total_modules}")
                if result.evidence:
                    for line in result.evidence.splitlines()[:8]:
                        self.logger("    " + line)

                # Continue through every implemented module after findings.
                if self.ctx.artifacts.get("http.rate_limited"):
                    self.logger("[!] Rate limit observed; remaining modules continue with bounded backoff.")
                # Explicit terminal-state heartbeat: the engine only advances
                # after this module returned, so a finding can never masquerade
                # as scan completion.
                self.logger(f"[complete] {module_name} reached terminal state: {result.status}")

            findings = self.ctx.artifacts.get("findings.detected", []) or []
            coverage = self.ctx.artifacts.get("scanner.payload_coverage", {}) or {}
            catalog = self.ctx.artifacts.get("payloads.catalog", {}) or {}
            self.logger(f"[+] All modules completed: {len(results)}/{total_modules}")
            self.logger(f"[+] Vulnerability findings: {len(findings)}")
            self.logger(f"[+] Payload catalog loaded: {sum(len(v) for v in catalog.values())} payload(s) across {len(catalog)} packs")
            if coverage:
                covered = sum(len(v) for v in coverage.values() if isinstance(v, list))
                executed = sum(1 for v in coverage.values() if isinstance(v, list) for row in v if isinstance(row, dict) and row.get("executed"))
                not_observed = sum(1 for v in coverage.values() if isinstance(v, list) for row in v if isinstance(row, dict) and row.get("status") == "not-observed")
                self.logger(f"[+] Payload execution ledger: {covered} catalog state(s); executed={executed}; not-observed={not_observed}")
            self.logger("[i] Scanner findings are exploit-verified only; raw exploit responses remain available in Repeater")
            self.logger("[+] Vulnerability scan complete — every selected module reached a terminal state")
            return results, self.ctx.artifacts.all()
        finally:
            # Do not let Playwright/httpx cleanup prevent the worker from
            # returning its completed result to the GUI.  In particular, a
            # remote page can leave browser shutdown waiting on network work.
            try:
                await asyncio.wait_for(self.ctx.close(), timeout=5.0)
            except asyncio.TimeoutError:
                self.logger("[!] Cleanup timed out after 5s; scan result is already complete")
            except asyncio.CancelledError:
                self.logger("[!] Cleanup cancelled; scan result is already complete")
            except Exception as exc:
                self.logger(f"[!] Cleanup warning: {exc}")
