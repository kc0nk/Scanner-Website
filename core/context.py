from __future__ import annotations
from urllib.parse import urljoin, urlparse
import re
from bs4 import BeautifulSoup
from core.artifacts import ArtifactStore
from core.flag import extract_flags, flag_to_regex
from core.models import SessionSnapshot, Target
from core.session import SessionHttpClient
from core.payloads import PAYLOAD_CATALOG, WRITEUP_DERIVED_PAYLOADS, payload_summary, total_payloads, writeup_payload_summary

class ExploitContext:
    def __init__(self,target:Target,session:SessionSnapshot,logger):
        self.target=target; self.session=session; self.logger=logger; self.flags=flag_to_regex(target.flag_format); self.flag_scanning_enabled=False; self.artifacts=ArtifactStore(); self.http=SessionHttpClient(session, logger=logger)
        self.artifacts.set("payloads.catalog", PAYLOAD_CATALOG)
        self.artifacts.set("payloads.summary", payload_summary())
        self.artifacts.set("payloads.total", total_payloads())
        self.artifacts.set("payloads.writeup_derived", WRITEUP_DERIVED_PAYLOADS)
        self.artifacts.set("payloads.writeup_summary", writeup_payload_summary())
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
    def add_finding(self, url, payload, vulnerability, response, *, confidence="medium", terminal_ready=False, request_raw=""):
        """Record a concrete finding and retain the exact request snapshot for replay.

        Scanner modules generally call this immediately after the probe request that
        produced the evidence. SessionHttpClient therefore keeps the last effective
        request (method, URL, headers, body, raw HTTP) so the UI can later clone the
        real request into Repeater instead of reconstructing a minimal GET/Host pair.
        """
        if not request_raw:
            snap = getattr(self.http, "last_request_snapshot", None)
            if isinstance(snap, dict):
                request_raw = snap.get("raw", "")
        finding = {
            "url": str(url or ""),
            "payload": str(payload or ""),
            "vulnerability": str(vulnerability or ""),
            "response": str(response or ""),
            "confidence": str(confidence or "medium"),
            "terminal_ready": bool(terminal_ready),
            "request_raw": str(request_raw or ""),
        }
        findings = self.artifacts.get("findings.detected", []) or []
        # Stable de-duplication by URL/vuln/payload.
        key = (finding["url"], finding["vulnerability"], finding["payload"])
        if not any((f.get("url"), f.get("vulnerability"), f.get("payload")) == key for f in findings if isinstance(f, dict)):
            findings.append(finding)
            self.artifacts.set("findings.detected", findings[-100:])
        return finding

    def scan_flags(self,*texts):
        if not getattr(self, "flag_scanning_enabled", False):
            return []
        found=[]
        for t in texts: found.extend(extract_flags(t,self.flags))
        found=list(dict.fromkeys(found))
        if found: self.artifacts.set('flags.found',list(dict.fromkeys((self.artifacts.get('flags.found',[]) or [])+found)))
        return found
    def inspect_source(self, url: str, source: str, payload: str | None = None, payload_index: int | None = None, content_type: str = ""):
        """Inspect raw response/source similarly to View Source (Ctrl+U).

        This is intentionally passive: it records source metadata, meta tags,
        comments, script references and flag matches for each probe.
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
        metadata["flags"] = []
        flags = []
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
        if flags:
            self.logger(f"[source]{suffix} FLAG match in {url}: {', '.join(flags)}")
        elif interesting:
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
