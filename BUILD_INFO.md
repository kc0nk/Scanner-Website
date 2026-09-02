# Desktop v3.45.0

- Removed the legacy external CLI transport; HTTP transport remains HTTPX/Playwright.
- Scanner methodology follows observed-request workflow: capture -> replay baseline -> controlled replay/mutation -> verify impact -> promote only confirmed exploit evidence.
- Business Logic / Workflow now verifies duplicate voucher/redeem behavior from captured traffic and performs at most one controlled replay per unique observed workflow.
- A verified workflow finding stores the follow-up authenticated response request for Scanner -> Repeater, so the real server response is replayed there without any flag extraction logic.
- Low-confidence inventory observations remain candidates and are not promoted into Vulnerability Findings.
- Duplicate findings are aggregated by URL + vulnerability.
- Dashboard/Finding table columns remain interactive and can be resized.
- Close action remains immediate hard-exit; obsolete graceful-shutdown helpers removed.
- Desktop UI/layout and existing module set are otherwise preserved.

- v3.45 expands the central CTF payload catalog and adds a Deep Payload Matrix module that executes applicable payloads on observed request surfaces.
- Vulnerability Findings now retain methodology, parameter, verification evidence, payload set, and the exact exploit request snapshot.
- Finding rows expose a Verification column and a double-click methodology/evidence view.
- Added document-upload verification canaries for HTML/SVG/XML/PDF/CSV; only browser-active HTML/SVG behavior is promoted automatically.
- Payload execution totals are reported from the execution ledger; the UI no longer claims every catalog payload ran when it did not.

## v3.45.0 Scanner Reset

- Scanner UI intentionally reset to an empty workspace for rebuild.
- Scanner payload catalog/exploit-command workflow is not exposed in the UI.
- Terminal navigation/action was removed.
- Intruder navigation/page was removed.
- Dashboard and Repeater remain available.
