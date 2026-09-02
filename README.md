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
