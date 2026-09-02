from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit
import re
import httpx
from bs4 import BeautifulSoup
from core.payloads import PAYLOADS

@dataclass
class RequestRecord:
    method: str
    status: int
    url: str
    content_type: str = ""
    size: int = 0
    response_body: str = ""

@dataclass
class PayloadRun:
    family: str
    payload: str
    url: str
    parameter: str
    status: int = 0
    size: int = 0
    evidence: str = ""
    error: str = ""

@dataclass
class AnalysisResult:
    target: str
    requests: list[RequestRecord] = field(default_factory=list)
    site_map: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    payload_runs: list[PayloadRun] = field(default_factory=list)

class WebAnalyzer:
    def __init__(self, timeout=12.0, max_pages=30):
        self.timeout = timeout
        self.max_pages = max_pages

    def run(self, target: str, log=None) -> AnalysisResult:
        target = target.strip()
        if not re.match(r"^https?://", target, re.I):
            target = "https://" + target
        target = target.rstrip("/")
        result = AnalysisResult(target=target)
        root = urlsplit(target)
        origin = f"{root.scheme}://{root.netloc}"
        queue = [target]
        seen = set()
        headers = {"User-Agent": "CTF-Exploit-Workbench/1.0 (Desktop Recon)"}
        with httpx.Client(timeout=self.timeout, follow_redirects=True, headers=headers, verify=False) as client:
            while queue and len(seen) < self.max_pages:
                url = queue.pop(0)
                if url in seen or urlsplit(url).netloc != root.netloc:
                    continue
                seen.add(url)
                try:
                    r = client.get(url)
                    ctype = r.headers.get("content-type", "")
                    body = r.content
                    result.requests.append(RequestRecord("GET", r.status_code, str(r.url), ctype, len(body), r.text[:200000]))
                    result.site_map.append(str(r.url))
                    if log: log(f"GET {r.status_code}  {r.url}")
                    if r.cookies:
                        for c in r.cookies.jar:
                            if c.name not in result.cookies: result.cookies.append(c.name)
                    server = r.headers.get("server", "")
                    powered = r.headers.get("x-powered-by", "")
                    for tech in (server, powered):
                        if tech and tech not in result.technologies: result.technologies.append(tech)
                    if "text/html" not in ctype.lower():
                        continue
                    soup = BeautifulSoup(body, "html.parser")
                    title = soup.title.get_text(" ", strip=True) if soup.title else ""
                    if title and log: log(f"  title: {title}")
                    for s in soup.find_all("script", src=True):
                        u = urljoin(str(r.url), s.get("src"))
                        if u not in result.js_files: result.js_files.append(u)
                    for form in soup.find_all("form"):
                        result.forms.append({"method": (form.get("method") or "GET").upper(), "action": urljoin(str(r.url), form.get("action") or "")})
                    for a in soup.find_all("a", href=True):
                        u = urljoin(str(r.url), a.get("href"))
                        sp = urlsplit(u)
                        clean = f"{sp.scheme}://{sp.netloc}{sp.path}" + (("?" + sp.query) if sp.query else "")
                        if sp.netloc == root.netloc and clean not in seen and clean not in queue and len(queue) < self.max_pages:
                            queue.append(clean)
                except Exception as e:
                    if log: log(f"ERR     {url}  {e}")

        # v1.0: payloads are automatic. There is no family/payload selector.
        # Every catalog payload is replayed against every discovered URL that
        # exposes a query parameter; URLs without parameters receive a benign
        # synthetic input parameter so the complete catalog is exercised.
        total = sum(len(v) for v in PAYLOADS.values()) * max(1, len(result.requests))
        completed = 0
        if log: log(f"PAYLOAD RUN: automatic catalog execution ({total} planned probes)")
        for rec in list(result.requests):
            sp = urlsplit(rec.url)
            params = [k for k, _ in __import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl(sp.query, keep_blank_values=True)]
            parameter = params[0] if params else "input"
            for family, payload_list in PAYLOADS.items():
                for payload in payload_list:
                    if params:
                        from urllib.parse import parse_qsl, urlencode, urlunsplit
                        pairs = parse_qsl(sp.query, keep_blank_values=True)
                        pairs[0] = (pairs[0][0], payload)
                        probe = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(pairs), sp.fragment))
                    else:
                        from urllib.parse import urlunsplit
                        probe = urlunsplit((sp.scheme, sp.netloc, sp.path, "input=" + __import__("urllib.parse", fromlist=["quote_plus"]).quote_plus(payload), sp.fragment))
                    run = PayloadRun(family, payload, probe, parameter)
                    try:
                        pr = client.request(rec.method, probe, content=None)
                        run.status = pr.status_code
                        run.size = len(pr.content)
                        low = pr.text.lower()[:200000]
                        markers = []
                        if family == "SSTI" and any(x in low for x in ("49", "<%=", "49")):
                            markers.append("template arithmetic marker")
                        if family == "LFI / Traversal" and any(x in low for x in ("root:", "localhost", "[boot loader]")):
                            markers.append("file-content marker")
                        if family == "Command Injection" and any(x in low for x in ("uid=", "gid=", "command not found")):
                            markers.append("command-output marker")
                        if family == "SQL Injection" and any(x in low for x in ("sql syntax", "mysql", "sqlite", "postgresql", "syntax error")):
                            markers.append("sql error marker")
                        if family == "XSS" and payload.lower() in low:
                            markers.append("reflection")
                        run.evidence = ", ".join(markers)
                    except Exception as e:
                        run.error = str(e)[:300]
                    result.payload_runs.append(run)
                    completed += 1
                    if log and (completed == total or completed % 25 == 0):
                        log(f"PAYLOAD {completed}/{total}  {family}  {parameter}  {run.status}  {payload[:70]}")
        if log: log(f"PAYLOAD RUN COMPLETE: {completed}/{total} probes executed")
        return result
