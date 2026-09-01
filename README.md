# CTF Exploit Workbench v3.29

Stability and HTTP-session update focused on Burp-like request replay.

- Repeater merges captured Cookie headers with the active browser cookie jar.
- Browser session cookies are preserved across Scanner and Repeater.
- Repeater follows redirects up to 10 hops.
- Dashboard response selection falls back to the latest same host/path response.
- Response preview retains full headers and body; Render is used for HTML.
- GUI workers retain their lifetime until QThread.finished.

- v3.29.0: SIGINT/SIGTERM are routed through Qt close handling to avoid KeyboardInterrupt inside closeEvent.

### Scanner coverage v3.29
The scanner registry includes JWT, XSS, SQLi, CSRF, CORS, 403 bypass, backup/sensitive-file discovery, SSRF, XXE, RCE, LFI, IDOR/BOLA, SSTI, NoSQL injection, prototype pollution, HPP, authentication bypass, and file-upload checks. Scanner results are vulnerability evidence only; flag extraction is not part of scanner findings.
