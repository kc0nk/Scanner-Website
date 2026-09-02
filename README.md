# CTF Exploit Workbench v3.35

Stability and HTTP-session update focused on Burp-like request replay.

- Repeater merges captured Cookie headers with the active browser cookie jar.
- Browser session cookies are preserved across Scanner and Repeater.
- Repeater follows redirects up to 10 hops.
- Dashboard response selection falls back to the latest same host/path response.
- Response preview retains full headers and body; Render is used for HTML.
- GUI workers retain their lifetime until QThread.finished.

- v3.35.0: SIGINT/SIGTERM are routed through Qt close handling to avoid KeyboardInterrupt inside closeEvent.

### Scanner coverage v3.35
The scanner registry includes JWT, XSS, SQLi, CSRF, CORS, 403 bypass, backup/sensitive-file discovery, SSRF, XXE, RCE, LFI, IDOR/BOLA, SSTI, NoSQL injection, prototype pollution, HPP, authentication bypass, and file-upload checks. Scanner results are vulnerability evidence only; the scanner performs no flag extraction or flag output. Any flag returned by the target remains ordinary HTTP response content and is visible only when that response is viewed in Repeater.


## v3.38 scanner completion fix
- A finding is non-terminal: the engine continues through the remaining modules.
- Browser bootstrap is bounded to 20 seconds.
- Browser/http cleanup is bounded to 5 seconds so a stalled Playwright shutdown cannot hide a completed scan from the GUI.
- Backup/Sensitive Files checks all payloads instead of returning on its first hit.
- The terminal explicitly reports when a finding was recorded and that scanning is continuing.


## v3.41 payload coverage
All payload packs in `core/payloads.py` are now represented by active scanner modules, including Security Headers and CORS / Header Differential. The scanner keeps processing every payload applicable to discovered request surfaces; findings never terminate a payload loop or module. FULL ORIGINAL REQUEST is the default transport policy.

## v3.45 exploit verification and payload coverage

The scanner uses observed requests as the source of truth, executes applicable public CTF/web-testing payloads, verifies technique-specific impact before promoting a finding, and preserves the exploit request, payload set, parameter, response evidence, and methodology for Repeater. Document upload checks include benign HTML/SVG/XML/PDF/CSV canaries. The scanner does not search for or extract challenge flags.

## v3.43 advanced coverage
The scanner includes additional CTF-oriented technique inventories for GraphQL, host-header/reverse-proxy behavior, cache-key anomalies, WebSocket surfaces, advanced HTTP desync indicators, business-logic workflows, mass assignment, OAuth/OIDC, race conditions, deserialization, and LDAP/XPath/XML injection. High-impact desync/state-changing actions are marked for manual confirmation rather than automatically replayed.

### v3.45.0 — Scanner reset
The Scanner is intentionally an empty shell while the exploitation workflow is rebuilt. Terminal and Intruder are removed from the navigation. Repeater remains available for manual request/response work.
