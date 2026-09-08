# CTF Exploit Workbench v3.0.0

v3.0 is traffic-driven: Web Analyzer consumes the HTTP History captured by the Chromium session.

Added analysis families:
- JWT Analysis (passive observation + controlled active probes)
- Auth & Access Control (non-mutating GET/HEAD/OPTIONS checks)
- Business Logic / Shop (non-mutating GET/HEAD checks)
- CORS observation

A finding is only CONFIRMED when family-specific evidence is present. Generic status/length changes do not confirm a vulnerability. JWT probes use the captured token context and a rejected invalid-signature control before marking an authentication/signature bypass CONFIRMED.

Payload references are curated from public web-security/CTF knowledge bases. The application does not scrape GitHub at runtime.
