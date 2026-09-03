# CTF Exploit Workbench v3.0

## History-driven Analyzer

Analyzer v3.0 treats Dashboard HTTP History as the primary evidence source. Start Analysis does not create a new crawl; it analyzes captured request/response records, extracts attack-surface inputs, and performs controlled tests only against observed parameters.

## Payload knowledge base

`core/payloads.py` contains a curated, normalized knowledge base derived from public CTF/web-security write-up references, including:

- w181496/Web-CTF-Cheatsheet
- Shiva108/CTF-notes
- riramar/Web-Attack-Cheat-Sheet
- 0xsyr0/Awesome-Cybersecurity-Handbooks
- Berkanktk/CyberSecurity

The engine uses applicability rules to select relevant families rather than sending every payload to every parameter. Each payload run records its source URLs for traceability.

A finding is only marked `CONFIRMED` when its family-specific evidence rule matches. Generic status/length changes remain `TESTED`.

## Run

```bash
python -m pip install -r requirements.txt
./run.sh
```
