# CTF Exploit Workbench v3.21

Stability and HTTP-session update focused on Burp-like request replay.

- Repeater merges captured Cookie headers with the active browser cookie jar.
- Browser session cookies are preserved across Scanner and Repeater.
- Repeater follows redirects up to 10 hops.
- Dashboard response selection falls back to the latest same host/path response.
- Response preview retains full headers and body; Render is used for HTML.
- GUI workers retain their lifetime until QThread.finished.
