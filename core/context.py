from __future__ import annotations
from urllib.parse import urljoin, urlparse
import re
from bs4 import BeautifulSoup
from core.artifacts import ArtifactStore
from core.models import SessionSnapshot, Target
from core.session import SessionHttpClient
from core.payloads import PAYLOAD_CATALOG, WRITEUP_DERIVED_PAYLOADS, payload_summary, total_payloads, writeup_payload_summary

class ExploitContext:
    def __init__(self,target:Target,session:SessionSnapshot,logger):
        self.target=target; self.session=session; self.logger=logger; self.artifacts=ArtifactStore(); self.http=SessionHttpClient(session, logger=logger)
        # Every scanner transport call automatically resolves the closest captured
        # browser request unless the module explicitly supplies its own context.
        # This makes FULL ORIGINAL REQUEST the default, not an opt-in.
        self.http.original_request_resolver = lambda method, url: self.original_request_for(method, url)
        self.artifacts.set("payloads.catalog", PAYLOAD_CATALOG)
        self.artifacts.set("payloads.summary", payload_summary())
        self.artifacts.set("payloads.total", total_payloads())
        self.artifacts.set("payloads.writeup_derived", WRITEUP_DERIVED_PAYLOADS)
        self.artifacts.set("payloads.writeup_summary", writeup_payload_summary())
        self.artifacts.set("scanner.payload_mode", "FULL ORIGINAL REQUEST")
        self.artifacts.set("scanner.payload_coverage", {})
        for k,v in {
            "session.cookies":session.cookies,"session.local_storage":session.local_storage,
            "browser.current_url":session.current_url,"browser.navigation_history":session.navigation_history,
            "browser.network_requests":session.network_requests,"browser.network_responses":session.network_responses,
            "browser.page_title":session.page_title}.items(): self.artifacts.set(k,v)
    async def close(self): await self.http.close()
    def in_scope(self,candidate):
        try: return urlparse(candidate).netloc==urlparse(self.target.url).netloc and urlparse(candidate).scheme in {"http","https"}
        except Exception: return False
    async def get_text(self,path_or_url=None):
        candidate=path_or_url or self.session.current_url or self.target.url
        url=candidate if candidate.startswith(("http://","https://")) else urljoin((self.session.current_url or self.target.url).rstrip('/')+'/',candidate.lstrip('/'))
        r=await self.http.request('GET',url); return r.text,str(r.url),r.status_code
    def request_corpus(self):
        """Normalized browser/form request inventory for method-aware scanning."""
        rows=[]; seen=set()
        for item in self.session.network_requests or []:
            if not isinstance(item, dict):
                continue
            url=str(item.get("url") or "")
            method=str(item.get("method") or "GET").upper()
            if not url or not self.in_scope(url):
                continue
            key=(method,url,str(item.get("post_data") or ""))
            if key in seen: continue
            seen.add(key)
            rows.append({"method":method,"url":url,"headers":dict(item.get("headers") or {}),"body":item.get("post_data") or "","resource_type":item.get("resource_type") or "","source":"browser"})
        for form in self.artifacts.get("recon.forms",[]) or []:
            if not isinstance(form,dict): continue
            method=str(form.get("method") or "GET").upper(); url=str(form.get("action") or "")
            if not url or not self.in_scope(url): continue
            fields=[(str(x.get("name")),str(x.get("value",""))) for x in (form.get("inputs") or []) if x.get("name")]
            key=(method,url,tuple(fields))
            if key in seen: continue
            seen.add(key)
            rows.append({"method":method,"url":url,"headers":{},"body":"","body_fields":fields,"resource_type":"form","source":"form"})
        return rows

    def original_request_for(self, method, url):
        """Return the closest captured browser request for a probe target.

        Scanner probes should mutate the captured request rather than inventing
        a new minimal GET. Exact method+URL matches win; a same-method/path
        match is used as a fallback. The returned dictionary is copied so a
        payload mutation can never alter browser history.
        """
        method = str(method or "GET").upper()
        url = str(url or "")
        rows = self.artifacts.get("recon.requests", []) or self.request_corpus()
        exact = None
        same_path = None
        try:
            target = urlparse(url)
        except Exception:
            target = None
        for row in rows:
            if not isinstance(row, dict):
                continue
            rm = str(row.get("method") or "GET").upper()
            ru = str(row.get("url") or "")
            if rm != method:
                continue
            if ru == url:
                exact = row
                break
            if target:
                try:
                    rp = urlparse(ru)
                    if rp.netloc == target.netloc and rp.path == target.path and same_path is None:
                        same_path = row
                except Exception:
                    pass
        source = exact or same_path
        if not source:
            return {"method": method, "url": url, "headers": {}, "body": "", "source": "scanner-fallback"}
        return {
            "method": str(source.get("method") or method).upper(),
            "url": str(source.get("url") or url),
            "headers": dict(source.get("headers") or {}),
            "body": source.get("body", source.get("post_data", "")) or "",
            "cookies": source.get("cookies", ""),
            "raw": source.get("raw") or source.get("raw_request") or "",
            "resource_type": source.get("resource_type", ""),
            "source": source.get("source", "browser"),
        }

    async def request_original(self, original, *, url=None, method=None, headers=None, body=None, **kwargs):
        """Send a scanner probe using the FULL ORIGINAL REQUEST context.

        Captured browser headers/cookies/body are retained. Explicit headers or
        body are treated only as payload mutations/overrides. This is the
        scanner equivalent of editing a Burp-style request while preserving
        the rest of the original request.
        """
        original = dict(original or {})
        req_method = str(method or original.get("method") or "GET").upper()
        req_url = str(url or original.get("url") or self.target.url)
        effective_headers = dict(original.get("headers") or {})
        effective_headers.update(dict(headers or {}))
        req_body = original.get("body", original.get("post_data", "")) if body is None else body
        return await self.http.request(
            req_method,
            req_url,
            headers=effective_headers,
            content=req_body if req_body not in (None, "") else None,
            original_request=original,
            **kwargs,
        )

    def mark_payload(self, module: str, payload: str, status: str = "tested", detail: str = "", *, executed: bool = True):
        """Record per-payload terminal state so the UI/engine can prove coverage.

        status is one of tested, finding, error, or not-applicable. A payload is
        never silently dropped: modules should mark it even when no suitable
        injection surface exists.
        """
        coverage = self.artifacts.get("scanner.payload_coverage", {}) or {}
        bucket = coverage.setdefault(str(module), [])
        row = {"payload": str(payload), "status": str(status), "detail": str(detail or ""), "executed": bool(executed)}
        # Last state wins for the same module/payload.
        for i, old in enumerate(bucket):
            if isinstance(old, dict) and old.get("payload") == row["payload"]:
                bucket[i] = row
                break
        else:
            bucket.append(row)
        self.artifacts.set("scanner.payload_coverage", coverage)
        return row

    def payload_catalog_for_module(self, module: str):
        """Return the canonical payload list associated with a module name."""
        from core.payloads import get_payloads
        return list(get_payloads(module) or [])

    def finalize_payload_coverage(self, module: str):
        """Close the ledger for a module without pretending skipped probes ran.

        Existing modules explicitly mark payloads when they execute them. Any
        catalog entry left unmarked is recorded as not-applicable/unknown rather
        than silently counted as tested. This makes coverage auditable.
        """
        expected = self.payload_catalog_for_module(module)
        coverage = self.artifacts.get("scanner.payload_coverage", {}) or {}
        bucket = coverage.setdefault(str(module), [])
        marked = {str(x.get("payload")): x for x in bucket if isinstance(x, dict)}
        for payload in expected:
            key = str(payload)
            if key not in marked:
                bucket.append({"payload": key, "status": "not-observed", "detail": "module completed without an explicit execution marker for this catalog entry", "executed": False})
        self.artifacts.set("scanner.payload_coverage", coverage)
        return bucket

    def add_finding(self, url, payload, vulnerability, response, *, confidence="medium", terminal_ready=False, request_raw="", parameter="", verification="", methodology=""):
        """Record a verified exploit evidence item without flooding the UI.

        Only high-confidence evidence is promoted to ``findings.detected``.
        Lower-confidence observations are retained separately as candidates.
        Findings are aggregated by URL + vulnerability so many payload hits do
        not spam the Dashboard. The effective request/response pair is retained
        for one-click replay in Repeater.
        """
        confidence = str(confidence or "medium").lower()
        snap = getattr(self.http, "last_request_snapshot", None)
        if not request_raw and isinstance(snap, dict):
            request_raw = snap.get("raw", "")
        finding = {
            "url": str(url or ""),
            "payload": str(payload or ""),
            "payloads": [str(payload or "")] if payload else [],
            "vulnerability": str(vulnerability or ""),
            "response": str(response or ""),
            "confidence": confidence,
            "verified": confidence == "high" or bool(terminal_ready),
            "terminal_ready": bool(terminal_ready),
            "request_raw": str(request_raw or ""),
            "request_method": str((snap or {}).get("method") or "GET"),
            "request_headers": dict((snap or {}).get("headers") or {}),
            "request_body": (snap or {}).get("body", b""),
            "request_mode": "FULL ORIGINAL REQUEST" if snap else "fallback",
            "parameter": str(parameter or ""),
            "verification": str(verification or ""),
            "methodology": str(methodology or f"Observe baseline -> mutate payload -> replay -> verify technique-specific evidence; payload={payload}"),
        }
        if confidence != "high" and not terminal_ready:
            candidates = self.artifacts.get("findings.candidates", []) or []
            candidates.append(finding)
            self.artifacts.set("findings.candidates", candidates[-200:])
            return finding

        findings = self.artifacts.get("findings.detected", []) or []
        key = (finding["url"], finding["vulnerability"])
        existing = next((f for f in findings if isinstance(f, dict) and
                         (f.get("url"), f.get("vulnerability")) == key), None)
        if existing is not None:
            payloads = list(existing.get("payloads") or [])
            if finding["payload"] and finding["payload"] not in payloads:
                payloads.append(finding["payload"])
            existing["payloads"] = payloads[-20:]
            existing["payload"] = existing["payload"] or finding["payload"]
            existing["response"] = finding["response"] or existing.get("response", "")
            existing["request_raw"] = finding["request_raw"] or existing.get("request_raw", "")
            existing["request_method"] = finding["request_method"]
            existing["request_headers"] = finding["request_headers"]
            existing["request_body"] = finding["request_body"]
            existing["verified"] = True
            existing["parameter"] = finding.get("parameter", existing.get("parameter", ""))
            existing["verification"] = finding.get("verification", existing.get("verification", ""))
            existing["methodology"] = finding.get("methodology", existing.get("methodology", ""))
            return existing
        findings.append(finding)
        self.artifacts.set("findings.detected", findings[-100:])
        return finding

    def inspect_source(self, url: str, source: str, payload: str | None = None, payload_index: int | None = None, content_type: str = ""):
        """Inspect raw response/source similarly to View Source (Ctrl+U).

        This is intentionally passive: it records source metadata, meta tags,
        comments, and script references for each probe.
        """
        text = source or ""
        content_type = content_type or ""
        lower = text.lower()
        metadata = {
            "url": url,
            "payload": payload,
            "payload_index": payload_index,
            "content_type": content_type,
            "length": len(text),
        }
        interesting = []
        # Raw HTML/source markers that are useful in CTF source review.
        for marker in ("<!--", "<meta", "<script", "sourceMappingURL", "debug", "secret", "admin", "token", "session"):
            if marker.lower() in lower:
                interesting.append(marker)
        meta_tags = []
        if "html" in content_type.lower() or "<html" in lower or "<meta" in lower:
            soup = BeautifulSoup(text, "html.parser")
            for tag in soup.find_all("meta"):
                meta_tags.append({k: v for k, v in tag.attrs.items() if isinstance(v, (str, int, float, list))})
            metadata["title"] = soup.title.get_text(" ", strip=True) if soup.title else ""
            metadata["meta_tags"] = meta_tags[:40]
            metadata["script_src"] = [str(x.get("src")) for x in soup.find_all("script") if x.get("src")][:40]
            comments = re.findall(r"<!--(.*?)-->", text, re.S)
            metadata["comments"] = [c.strip()[:500] for c in comments[:20]]
        metadata["interesting_markers"] = interesting
        key = "source.inspect"
        history = self.artifacts.get(key, []) or []
        history.append(metadata)
        self.artifacts.set(key, history[-200:])
        # Emit compact source findings immediately so each payload has visible
        # Ctrl+U-style feedback without flooding the UI with whole pages.
        if payload_index is not None:
            suffix = f" payload #{payload_index}"
        else:
            suffix = ""
        if interesting:
            self.logger(f"[source]{suffix} {url} -> len={len(text)} markers={', '.join(interesting[:8])}")
        return metadata

    @staticmethod
    def discover_links(base_url,html):
        soup=BeautifulSoup(html,'html.parser'); out=[]
        for tag in soup.find_all(['a','form','script','link']):
            attr='href' if tag.name in {'a','link'} else ('action' if tag.name=='form' else 'src'); value=tag.get(attr)
            if value and not value.startswith(('javascript:','mailto:','#','data:')): out.append(urljoin(base_url,value))
        return list(dict.fromkeys(out))
    @staticmethod
    def discover_forms(base_url,html):
        soup=BeautifulSoup(html,'html.parser'); forms=[]
        for form in soup.find_all('form'):
            inputs=[]
            for node in form.find_all(['input','textarea','select']): inputs.append({'name':node.get('name'),'value':node.get('value',''),'type':node.get('type',node.name)})
            forms.append({'action':urljoin(base_url,form.get('action','')),'method':form.get('method','GET').upper(),'inputs':inputs})
        return forms
    @staticmethod
    def discover_csrf(html):
        soup=BeautifulSoup(html,'html.parser'); vals=[]
        for node in soup.find_all('input'):
            name=(node.get('name') or '').lower(); value=node.get('value')
            if value and ('csrf' in name or 'token' in name): vals.append((node.get('name'),value))
        for node in soup.find_all('meta'):
            name=(node.get('name') or '').lower(); value=node.get('content')
            if value and 'csrf' in name: vals.append((node.get('name'),value))
        return list(dict.fromkeys(vals))
    @staticmethod
    def normalize_urls(urls,scope_netloc):
        out=[]; seen=set()
        for value in urls:
            try:
                p=urlparse(value)
                if p.netloc!=scope_netloc or p.scheme not in {'http','https'}: continue
                clean=value.split('#',1)[0]
                if clean not in seen: seen.add(clean); out.append(clean)
            except Exception: pass
        return out
