# CTF Exploit Workbench v3.0.0

v3.0 is traffic-driven: Web Analyzer consumes the HTTP History captured by the Chromium session.

Added analysis families:
- JWT Analysis (passive observation + controlled active probes)
- Auth & Access Control (non-mutating GET/HEAD/OPTIONS checks)
- Business Logic / Shop (non-mutating GET/HEAD checks)
- CORS observation

A finding is only CONFIRMED when family-specific evidence is present. Generic status/length changes do not confirm a vulnerability. JWT probes use the captured token context and a rejected invalid-signature control before marking an authentication/signature bypass CONFIRMED.

Payload references are curated from public web-security/CTF knowledge bases. The application does not scrape GitHub at runtime.

## CONFIRMED evidence policy (v3.0)

`CONFIRMED` is reserved for family-specific evidence. Generic HTTP status, body-length, or response-difference changes are never sufficient.

Current strong confirmation rules:
- SQL Injection: a database error signature appears in the mutated response and was absent from the baseline.
- SSTI: template arithmetic output (`49`/`49.0`) appears only after the template probe.
- LFI / Traversal: a file-content signature such as `root:x:`/`root:*:` or a boot-loader marker appears only after traversal.
- Command Injection: command identity output (`uid=`/`gid=`) appears only after the command probe.
- Open Redirect: the response contains an external `Location` header.
- JWT: the original token must be accepted live; the invalid-signature control must be rejected; then the selected JWT mutation must be accepted. Redirects are not followed for these decisions.

Conservative families stay `TESTED` until an independent oracle is available: XSS (requires execution proof), SSRF (requires server-side callback proof), NoSQL injection, XXE, IDOR/BOLA, access-control bypass, and business-logic flaws.
