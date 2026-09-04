# CTF Exploit Workbench v3.0.0

v3.0 is traffic-driven: Web Analyzer consumes the HTTP History captured by the Chromium session.

Added analysis families:
- JWT Analysis (passive observation)
- Auth & Access Control (non-mutating GET/HEAD/OPTIONS checks)
- Business Logic / Shop (non-mutating GET/HEAD checks)
- CORS observation

A finding is only CONFIRMED when family-specific evidence is present. Generic status/length changes do not confirm a vulnerability.

Payload references are curated from public web-security/CTF knowledge bases. The application does not scrape GitHub at runtime.
