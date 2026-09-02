from __future__ import annotations

import re
from urllib.parse import urljoin

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


PDF_CANARY = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /OpenAction 2 0 R /Pages 3 0 R >>
endobj
2 0 obj
<< /S /JavaScript /JS (app.alert('CTF-WORKBENCH-PDF-CANARY')) >>
endobj
3 0 obj
<< /Type /Pages /Count 0 /Kids [] >>
endobj
trailer
<< /Root 1 0 R >>
%%EOF
"""
SVG_CANARY = b"<svg xmlns='http://www.w3.org/2000/svg'><text>CTF-WORKBENCH-SVG-CANARY</text></svg>"
HTML_CANARY = b"<!doctype html><html><body><x-ctf data-probe='ctf-upload-canary'>CTF-WORKBENCH-HTML-CANARY</x-ctf></body></html>"
XML_CANARY = b"<?xml version='1.0'?><probe>CTF-WORKBENCH-XML-CANARY</probe>"
CSV_CANARY = b"=1+1,CTF-WORKBENCH-CSV-CANARY\n"


class DocumentUploadModule(ExploitModule):
    """Verify unsafe document upload behavior using benign canary files."""

    name = "File Upload / Document Active Content"
    category = "upload"

    @staticmethod
    def _file_for(label: str):
        label = label.lower()
        if label == "pdf-javascript-canary" or label == "pdf-openaction-canary":
            return "ctf_workbench_canary.pdf", "application/pdf", PDF_CANARY
        if label == "svg-canary":
            return "ctf_workbench_canary.svg", "image/svg+xml", SVG_CANARY
        if label == "html-canary":
            return "ctf_workbench_canary.html", "text/html", HTML_CANARY
        if label == "xml-canary":
            return "ctf_workbench_canary.xml", "application/xml", XML_CANARY
        if label == "csv-formula-canary":
            return "ctf_workbench_canary.csv", "text/csv", CSV_CANARY
        return None

    @staticmethod
    def _find_url(text: str, base: str) -> str | None:
        # Conservative extraction of an absolute or root-relative URL from JSON/HTML.
        m = re.search(r'https?://[^\"\'\s<>]+', text or "")
        if m:
            return m.group(0)
        m = re.search(r'(?:(?:href|src|url|path|file)["\']?\s*[:=]\s*["\'])(/[^"\']+)', text or "", re.I)
        return urljoin(base, m.group(1)) if m else None

    async def run(self, ctx):
        forms = [f for f in (ctx.artifacts.get("recon.forms", []) or []) if str(f.get("method") or "GET").upper() == "POST"]
        evidence = []
        verified = 0
        payloads = get_payloads(self.name)
        for form in forms[:20]:
            file_inputs = [x for x in form.get("inputs", []) if str(x.get("type") or "").lower() == "file"]
            if not file_inputs:
                continue
            action = str(form.get("action") or ctx.target.url)
            field = str(file_inputs[0].get("name") or "file")
            for payload in payloads:
                spec = self._file_for(payload)
                if not spec:
                    ctx.mark_payload(self.name, payload, "not-applicable", "unknown document canary")
                    continue
                filename, mime, content = spec
                try:
                    response = await ctx.http.request(
                        "POST", action,
                        files={field: (filename, content, mime)},
                        data={},
                    )
                    text = response.text or ""
                    stored = self._find_url(text, action)
                    # A confirmed browser-executable upload requires the server to
                    # accept the file AND expose its content back with an active MIME
                    # type. Merely accepting a PDF is not enough.
                    if stored and payload == "html-canary":
                        follow = await ctx.http.request("GET", stored)
                        active = "text/html" in str(follow.headers.get("content-type", "")).lower() and "ctf-upload-canary" in follow.text
                    elif stored and payload == "svg-canary":
                        follow = await ctx.http.request("GET", stored)
                        active = "image/svg+xml" in str(follow.headers.get("content-type", "")).lower() and "ctf-workbench-svg-canary" in follow.text
                    else:
                        active = False
                    if active:
                        verified += 1
                        ctx.mark_payload(self.name, payload, "finding", f"uploaded and served as active content at {stored}")
                        ctx.add_finding(
                            stored,
                            payload,
                            self.name,
                            f"HTTP {follow.status_code}; uploaded canary served as active content; upload={action}",
                            confidence="high",
                            request_raw=getattr(ctx.http, "last_request_snapshot", {}).get("raw", ""),
                        )
                        evidence.append(f"[VERIFIED] {payload} -> {stored}; active content served")
                    else:
                        ctx.mark_payload(self.name, payload, "tested", f"HTTP {response.status_code}; stored_url={bool(stored)}")
                        evidence.append(f"[tested] {payload} -> HTTP {response.status_code}; stored_url={stored or 'none'}")
                except Exception as exc:
                    ctx.mark_payload(self.name, payload, "error", str(exc), executed=False)
                    evidence.append(f"[error] {payload}: {exc}")
        return ExploitResult(
            self.name,
            "success" if verified else ("signal" if evidence else "no-signal"),
            f"Document upload verification completed: verified={verified}",
            evidence="\n".join(evidence[:80]),
        )
