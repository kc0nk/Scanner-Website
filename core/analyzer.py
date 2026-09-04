from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, parse_qsl, urlencode, urlunsplit, quote_plus
import json
import re
import httpx
from bs4 import BeautifulSoup
from core.payloads import PAYLOADS, PAYLOAD_CATALOG, applicable_families, source_urls_for


@dataclass
class RequestRecord:
    method: str
    status: int
    url: str
    content_type: str = ""
    size: int = 0
    response_body: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    duration_ms: int = 0


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
    state: str = "TESTED"
    baseline_status: int = 0
    baseline_size: int = 0
    baseline_body: str = ""
    test_body: str = ""
    baseline_request: str = ""
    test_request: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    diff_summary: str = ""
    method: str = "GET"
    source_urls: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    target: str
    requests: list[RequestRecord] = field(default_factory=list)
    site_map: list[str] = field(default_factory=list)
    network: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    websockets: list[str] = field(default_factory=list)
    payload_runs: list[PayloadRun] = field(default_factory=list)


class WebAnalyzer:
    """Passive web analyzer plus controlled CTF-oriented payload replay.

    The analyzer is designed for targets the user is explicitly analyzing.
    It stays on the supplied host for crawling and records the discovered
    artifacts so the UI can present an analyst-style report.
    """

    SECRET_PATTERNS = [
        re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|password|passwd|authorization)\b\s*[:=]\s*[\"']?([^\s\"'&,]{6,})"),
        re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"(?i)\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
        re.compile(r"(?i)\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b"),
        re.compile(r"(?i)-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
    ]

    TECH_PATTERNS = [
        (re.compile(r"(?i)wp-content|wp-includes"), "WordPress"),
        (re.compile(r"(?i)__next_data__|/_next/"), "Next.js"),
        (re.compile(r"(?i)react(?:\.production)?\.min\.js|data-reactroot"), "React"),
        (re.compile(r"(?i)vue(?:\.runtime)?\.min\.js|data-v-[a-z]"), "Vue.js"),
        (re.compile(r"(?i)angular(?:\.min)?\.js|ng-version"), "Angular"),
        (re.compile(r"(?i)laravel_session|laravel"), "Laravel"),
        (re.compile(r"(?i)django|csrftoken"), "Django"),
    ]

    def __init__(self, timeout: float = 12.0, max_pages: int = 30):
        self.timeout = timeout
        self.max_pages = max_pages

    @staticmethod
    def _normalize_target(target: str) -> str:
        target = target.strip()
        if not re.match(r"^https?://", target, re.I):
            target = "https://" + target
        return target.rstrip("/")

    @staticmethod
    def _same_origin(root, url: str) -> bool:
        sp = urlsplit(url)
        return sp.scheme in {"http", "https"} and sp.netloc == root.netloc

    @staticmethod
    def _clean_url(url: str) -> str:
        sp = urlsplit(url)
        return urlunsplit((sp.scheme, sp.netloc, sp.path or "/", sp.query, ""))

    def _extract_secrets(self, text: str, source: str, result: AnalysisResult):
        if not text:
            return
        sample = text[:250000]
        for pattern in self.SECRET_PATTERNS:
            for match in pattern.finditer(sample):
                token = match.group(0).strip()
                value = f"{source}: {token[:220]}"
                if value not in result.secrets:
                    result.secrets.append(value)

    def _detect_technologies(self, response: httpx.Response, body: str, result: AnalysisResult):
        headers = response.headers
        for name in (headers.get("server", ""), headers.get("x-powered-by", "")):
            if name and name not in result.technologies:
                result.technologies.append(name)
        haystack = "\n".join([
            body[:200000],
            " ".join(f"{k}: {v}" for k, v in headers.items()),
        ])
        for pattern, technology in self.TECH_PATTERNS:
            if pattern.search(haystack) and technology not in result.technologies:
                result.technologies.append(technology)

    def _extract_forms(self, soup: BeautifulSoup, base_url: str, result: AnalysisResult):
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            action = urljoin(base_url, form.get("action") or "")
            inputs = []
            for element in form.find_all(["input", "textarea", "select", "button"]):
                name = element.get("name") or ""
                if name:
                    inputs.append({
                        "name": name,
                        "type": element.get("type") or element.name,
                    })
            result.forms.append({"method": method, "action": self._clean_url(action), "inputs": inputs})

    def _discover_links(self, soup: BeautifulSoup, base_url: str, root, queue: list[str], seen: set[str]):
        for anchor in soup.find_all("a", href=True):
            raw = (anchor.get("href") or "").strip()
            if not raw or raw.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue
            absolute = urljoin(base_url, raw)
            if not self._same_origin(root, absolute):
                continue
            clean = self._clean_url(absolute)
            if clean not in seen and clean not in queue and len(queue) < self.max_pages * 2:
                queue.append(clean)

    @staticmethod
    def _header_get(headers: dict[str, str], name: str) -> str:
        target = name.lower()
        return next((v for k, v in headers.items() if str(k).lower() == target), "")

    @staticmethod
    def _request_text(method: str, url: str, headers: dict[str, str], body: str = "") -> str:
        sp = urlsplit(url)
        request_line = f"{method.upper()} {sp.path or '/'}"
        if sp.query:
            request_line += f"?{sp.query}"
        request_line += " HTTP/1.1"
        lines = [request_line]
        lines.extend(f"{k}: {v}" for k, v in headers.items())
        if body:
            lines.extend(["", body])
        return "\n".join(lines)

    @staticmethod
    def _mutate_observed_input(rec, parameter: str, payload: str):
        url = str(getattr(rec, "url", "") or "")
        method = str(getattr(rec, "method", "GET") or "GET").upper()
        headers = dict(getattr(rec, "request_headers", {}) or {})
        body = str(getattr(rec, "request_body", "") or "")
        sp = urlsplit(url)

        query_pairs = parse_qsl(sp.query, keep_blank_values=True)
        if any(k == parameter for k, _ in query_pairs):
            replaced = False
            mutated = []
            for key, value in query_pairs:
                if key == parameter and not replaced:
                    mutated.append((key, payload))
                    replaced = True
                else:
                    mutated.append((key, value))
            new_url = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(mutated), ""))
            return new_url, headers, body

        content_type = WebAnalyzer._header_get(headers, "content-type").lower()
        if body and "application/x-www-form-urlencoded" in content_type:
            pairs = parse_qsl(body, keep_blank_values=True)
            if any(k == parameter for k, _ in pairs):
                replaced = False
                mutated = []
                for key, value in pairs:
                    if key == parameter and not replaced:
                        mutated.append((key, payload))
                        replaced = True
                    else:
                        mutated.append((key, value))
                return url, headers, urlencode(mutated)

        if body and "application/json" in content_type:
            try:
                obj = json.loads(body)
                if isinstance(obj, dict) and parameter in obj and isinstance(obj[parameter], (str, int, float, bool, type(None))):
                    obj[parameter] = payload
                    return url, headers, json.dumps(obj, separators=(",", ":"))
            except Exception:
                pass
        return None

    @staticmethod
    def _diff_summary(baseline_status: int, test_status: int, baseline_size: int, test_size: int, baseline_body: str, test_body: str) -> str:
        parts = []
        if baseline_status != test_status:
            parts.append(f"status {baseline_status}→{test_status}")
        if baseline_size != test_size:
            parts.append(f"length {baseline_size}→{test_size} ({test_size-baseline_size:+d})")
        if baseline_body != test_body:
            parts.append("body changed")
        return "; ".join(parts) if parts else "no observable response difference"

    def _evidence_for(self, family: str, payload: str, baseline_body: str, test_body: str, baseline_status: int, test_status: int, response_headers: dict[str, str], url: str) -> tuple[str, str]:
        """Return (state, evidence) using explicit evidence rules only.

        CONFIRMED means the test produced a family-specific observable artifact;
        generic status/length changes alone are never sufficient.
        """
        b = (baseline_body or "").lower()
        t = (test_body or "").lower()
        headers = {str(k).lower(): str(v) for k, v in (response_headers or {}).items()}

        if family == "SQL Injection":
            markers = ("sql syntax", "mysql", "mariadb", "sqlite", "postgresql", "ora-", "odbc sql", "syntax error at or near")
            hit = next((m for m in markers if m in t and m not in b), "")
            if hit:
                return "CONFIRMED", f"database error signature introduced: {hit}"
            return "TESTED", "no database error signature introduced"

        if family == "XSS":
            if payload.lower() in t and payload.lower() not in b:
                return "TESTED", "payload reflection observed (execution not proven)"
            return "TESTED", "no payload reflection observed"

        if family == "SSTI":
            if any(marker in t and marker not in b for marker in ("49", "49.0")):
                return "CONFIRMED", "template arithmetic output observed"
            return "TESTED", "template evaluation not proven"

        if family == "LFI / Traversal":
            for marker in ("root:x:", "root:", "[boot loader]", "localhost"):
                if marker in t and marker not in b:
                    return "CONFIRMED", f"file-content signature introduced: {marker}"
            return "TESTED", "no file-content signature introduced"

        if family == "Command Injection":
            for marker in ("uid=", "gid=", "command not found"):
                if marker in t and marker not in b:
                    return "CONFIRMED", f"command-output signature introduced: {marker}"
            return "TESTED", "no command-output signature introduced"

        if family == "Open Redirect":
            location = headers.get("location", "")
            if location and urlsplit(location).netloc and urlsplit(location).netloc != urlsplit(url).netloc:
                return "CONFIRMED", f"external Location header observed: {location}"
            return "TESTED", "no external redirect observed"

        if family == "SSRF":
            for marker in ("localhost", "127.0.0.1", "connection refused", "internal server"):
                if marker in t and marker not in b:
                    return "TESTED", f"internal-target response marker observed: {marker} (server-side fetch not independently proven)"
            return "TESTED", "no internal-target response marker observed"

        if family == "NoSQL Injection":
            markers = ("mongodb", "bson", "$ne", "$gt", "cast to object")
            if any(m in t and m not in b for m in markers):
                return "TESTED", "NoSQL-related response marker observed (injection not independently proven)"
            return "TESTED", "no NoSQL-specific evidence observed"

        if family == "XXE":
            for marker in ("root:x:", "localhost", "<!doctype", "entity"):
                if marker in t and marker not in b:
                    return "TESTED", f"XXE-related marker observed: {marker} (external entity resolution not independently proven)"
            return "TESTED", "no XXE-specific evidence observed"

        if family == "Business Logic / Shop":
            # Keep this family conservative: response deltas alone never confirm a pricing/bypass flaw.
            return "TESTED", "business-logic mutation observed; purchase/discount bypass requires explicit semantic validation"

        if family == "Auth & Access Control":
            return "TESTED", "access-control surface observed; authorization bypass requires an authenticated-vs-unauthenticated semantic comparison"

        if family == "JWT Analysis":
            return "TESTED", "JWT token observed/inspected; cryptographic or authorization weakness not independently proven"

        if family == "CORS":
            return "TESTED", "CORS header observed; exploitability requires origin/credential validation"

        return "TESTED", "no confirming evidence rule matched"

    @staticmethod
    def _is_jwt(value: str) -> bool:
        value = (value or "").strip()
        if value.lower().startswith("bearer "):
            value = value.split(None, 1)[1].strip()
        return bool(re.fullmatch(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value))

    def _passive_special_checks(self, rec, result: AnalysisResult):
        """Record factual auth/control observations without claiming exploitation."""
        req_headers = {str(k).lower(): str(v) for k, v in (getattr(rec, "request_headers", {}) or {}).items()}
        auth = req_headers.get("authorization", "")
        if self._is_jwt(auth):
            note = f"JWT observed in Authorization header: {getattr(rec, 'url', '')}"
            if note not in result.secrets:
                result.secrets.append(note)

        cookie_header = req_headers.get("cookie", "")
        for part in cookie_header.split(";"):
            if "=" not in part:
                continue
            name, value = [x.strip() for x in part.split("=", 1)]
            if self._is_jwt(value):
                note = f"JWT observed in Cookie '{name}': {getattr(rec, 'url', '')}"
                if note not in result.secrets:
                    result.secrets.append(note)

        resp_headers = {str(k).lower(): str(v) for k, v in (getattr(rec, "response_headers", {}) or {}).items()}
        acao = resp_headers.get("access-control-allow-origin", "")
        acac = resp_headers.get("access-control-allow-credentials", "")
        if acao:
            cors_note = f"CORS observed: ACAO={acao}" + (f"; ACAC={acac}" if acac else "") + f" on {getattr(rec, 'url', '')}"
            if cors_note not in result.network:
                result.network.append(cors_note)

        # Record ID-like object references as an attack-surface observation.
        # This is deliberately passive: proving IDOR/BOLA requires an appropriate
        # second authorization context and is never inferred from the identifier alone.
        url = str(getattr(rec, "url", "") or "")
        object_tokens = re.findall(r"(?:^|[/?&_=.-])(\d{1,12})(?=$|[/?&_=.-])", url)
        if object_tokens:
            note = f"ID-like object reference observed: {url}"
            if note not in result.network:
                result.network.append(note)

    def _probe_payloads(self, client: httpx.Client, result: AnalysisResult, log=None):
        query_records = []
        for rec in result.requests:
            method = rec.method.upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                continue
            # Only test input surfaces actually observed in the captured request.
            params = [k for k, _ in parse_qsl(urlsplit(rec.url).query, keep_blank_values=True)]
            if not params:
                ctype = self._header_get(rec.request_headers, "content-type").lower()
                if rec.request_body and "application/x-www-form-urlencoded" in ctype:
                    params = [k for k, _ in parse_qsl(rec.request_body, keep_blank_values=True)]
                elif rec.request_body and "application/json" in ctype:
                    try:
                        obj = json.loads(rec.request_body)
                        if isinstance(obj, dict):
                            params = list(obj.keys())
                    except Exception:
                        pass
            for parameter in dict.fromkeys(params):
                query_records.append((rec, parameter))

        total = 0
        for rec, parameter in query_records:
            ctype = self._header_get(rec.request_headers, "content-type").lower()
            families = []
            for family in applicable_families(parameter, ctype, body=rec.request_body):
                meta = PAYLOAD_CATALOG.get(family, {})
                if meta.get("passive_only"):
                    continue
                allowed_methods = set(meta.get("methods", []))
                if allowed_methods and rec.method.upper() not in allowed_methods:
                    continue
                families.append(family)
            total += sum(len(PAYLOADS.get(family, [])) for family in families)
        if log:
            log(f"PAYLOAD RUN: {total} controlled probes planned from observed HTTP History inputs")
        completed = 0

        for rec, parameter in query_records:
            ctype = self._header_get(rec.request_headers, "content-type").lower()
            families = []
            for family in applicable_families(parameter, ctype, body=rec.request_body):
                meta = PAYLOAD_CATALOG.get(family, {})
                if meta.get("passive_only"):
                    continue
                allowed_methods = set(meta.get("methods", []))
                if allowed_methods and rec.method.upper() not in allowed_methods:
                    continue
                families.append(family)
            for family in families:
                for payload in PAYLOADS.get(family, []):
                    mutation = self._mutate_observed_input(rec, parameter, payload)
                    if not mutation:
                        continue
                    probe, headers, body = mutation
                    run = PayloadRun(
                        family=family,
                        payload=payload,
                        url=probe,
                        parameter=parameter,
                        baseline_status=rec.status,
                        baseline_size=rec.size,
                        baseline_body=rec.response_body[:200000],
                        baseline_request=self._request_text(rec.method, rec.url, rec.request_headers, rec.request_body),
                        test_request=self._request_text(rec.method, probe, headers, body),
                        source_urls=source_urls_for(family),
                    )
                    try:
                        follow_redirects = family != "Open Redirect"
                        pr = client.request(
                            rec.method,
                            probe,
                            headers=headers,
                            content=body.encode("utf-8") if body else None,
                            follow_redirects=follow_redirects,
                        )
                        run.status = pr.status_code
                        run.size = len(pr.content)
                        run.test_body = pr.text[:200000]
                        run.response_headers = dict(pr.headers)
                        run.diff_summary = self._diff_summary(
                            run.baseline_status, run.status,
                            run.baseline_size, run.size,
                            run.baseline_body, run.test_body,
                        )
                        run.state, run.evidence = self._evidence_for(
                            family, payload,
                            run.baseline_body, run.test_body,
                            run.baseline_status, run.status,
                            run.response_headers, probe,
                        )
                    except Exception as exc:
                        run.error = str(exc)[:300]
                        run.state = "TESTED"
                    result.payload_runs.append(run)
                    completed += 1
                    if log and (completed == total or completed % 25 == 0):
                        log(f"PAYLOAD {completed}/{total} {family} {parameter} {run.state} {run.status}")
        if log:
            confirmed = sum(1 for x in result.payload_runs if x.state == "CONFIRMED")
            log(f"PAYLOAD RUN COMPLETE: {completed}/{total} probes executed • {confirmed} confirmed by evidence")

    @staticmethod
    def _target_from_records(records) -> str:
        for rec in records or []:
            url = str(getattr(rec, "url", "") or "")
            if re.match(r"^https?://", url, re.I):
                return WebAnalyzer._normalize_target(url)
        return ""

    def _passive_record_analysis(self, records, result: AnalysisResult, log=None):
        """Analyze already-captured browser traffic without re-crawling the target."""
        root = urlsplit(result.target) if result.target else None
        for idx, rec in enumerate(records or [], 1):
            url = str(getattr(rec, "url", "") or "")
            if not url or not re.match(r"^https?://", url, re.I):
                continue
            if root and not self._same_origin(root, url):
                # Keep analyzer aligned with the selected browser session's target host.
                continue

            method = str(getattr(rec, "method", "GET") or "GET").upper()
            status = int(getattr(rec, "status", 0) or 0)
            mime = str(getattr(rec, "mime_type", "") or "")
            body = str(getattr(rec, "response_body", "") or "")
            size = int(getattr(rec, "response_size", 0) or 0)
            req_headers = dict(getattr(rec, "request_headers", {}) or {})
            resp_headers = dict(getattr(rec, "response_headers", {}) or {})
            self._passive_special_checks(rec, result)

            result.requests.append(RequestRecord(
                method=method,
                status=status,
                url=url,
                content_type=mime,
                size=size or len(body.encode("utf-8", errors="ignore")),
                response_body=body,
                request_headers=req_headers,
                request_body=str(getattr(rec, "request_body", "") or ""),
                response_headers=resp_headers,
                duration_ms=int(getattr(rec, "duration_ms", 0) or 0),
            ))
            result.network.append(f"{method} {status or '…'} {url}")
            if self._clean_url(url) not in result.site_map:
                result.site_map.append(self._clean_url(url))

            # Request cookies and response Set-Cookie values observed in Chrome.
            for key, value in req_headers.items():
                if key.lower() == "cookie" and value:
                    for part in value.split(";"):
                        name = part.strip().split("=", 1)[0].strip()
                        if name:
                            summary = f"{name}; domain={urlsplit(url).netloc}; source=request"
                            if summary not in result.cookies:
                                result.cookies.append(summary)
            for key, value in resp_headers.items():
                if key.lower() == "set-cookie" and value:
                    name = value.split("=", 1)[0].strip()
                    summary = f"{name}; domain={urlsplit(url).netloc}; source=response"
                    if summary not in result.cookies:
                        result.cookies.append(summary)

            # Passive technologies from observed headers/body.
            haystack = "\n".join([body[:200000], " ".join(f"{k}: {v}" for k, v in resp_headers.items())])
            for header_name in ("server", "x-powered-by", "via"):
                value = next((v for k, v in resp_headers.items() if k.lower() == header_name), "")
                if value and value not in result.technologies:
                    result.technologies.append(value)
            for pattern, technology in self.TECH_PATTERNS:
                if pattern.search(haystack) and technology not in result.technologies:
                    result.technologies.append(technology)

            # Secrets, WebSocket endpoints, JS references and HTML forms from captured responses.
            self._extract_secrets(body, url, result)
            for ws_match in re.findall(r"wss?://[^\s\"'<>]+", body, re.I):
                if ws_match not in result.websockets:
                    result.websockets.append(ws_match)
            if getattr(rec, "resource_type", "") == "WebSocket" or url.lower().startswith(("ws://", "wss://")):
                if url not in result.websockets:
                    result.websockets.append(url)

            if mime.lower().split(";", 1)[0].strip() in {"text/html", "application/xhtml+xml"} or "<form" in body[:50000].lower():
                try:
                    soup = BeautifulSoup(body.encode("utf-8", errors="ignore"), "html.parser")
                    self._extract_forms(soup, url, result)
                    for script in soup.find_all("script", src=True):
                        script_url = self._clean_url(urljoin(url, script.get("src")))
                        if script_url not in result.js_files:
                            result.js_files.append(script_url)
                    for script in soup.find_all("script"):
                        inline = script.string or script.get_text(" ", strip=True)
                        if inline:
                            self._extract_secrets(inline, f"inline:{url}", result)
                            for ws_match in re.findall(r"wss?://[^\s\"'<>]+", inline, re.I):
                                if ws_match not in result.websockets:
                                    result.websockets.append(ws_match)
                except Exception as exc:
                    if log:
                        log(f"PASSIVE PARSE ERR {url}: {exc}")

            if log and (idx == 1 or idx % 10 == 0):
                log(f"PASSIVE {idx}/{len(records)} {method} {status or '…'} {url}")

        if log:
            log(f"PASSIVE ANALYSIS COMPLETE: {len(result.requests)} captured requests")

    def run_from_history(self, records, target: str = "", log=None) -> AnalysisResult:
        """Analyze the HTTP History captured by Chromium in the Dashboard."""
        target = self._normalize_target(target) if target else self._target_from_records(records)
        result = AnalysisResult(target=target)
        if not records:
            if log:
                log("ANALYSIS STOPPED: HTTP History is empty")
            return result
        if not target:
            if log:
                log("ANALYSIS STOPPED: no HTTP/HTTPS target found in history")
            return result

        self._passive_record_analysis(records, result, log=log)

        # Replay probes only against parameters that were actually observed in HTTP History.
        with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=False,
                          headers={"User-Agent": "CTF-Exploit-Workbench/3.0 (History Analyzer)"}) as client:
            self._probe_payloads(client, result, log=log)

        for field_name in ("site_map", "network", "js_files", "technologies", "cookies", "secrets", "websockets"):
            setattr(result, field_name, list(dict.fromkeys(getattr(result, field_name))))
        seen_forms = set(); unique_forms = []
        for item in result.forms:
            key = (item.get("method"), item.get("action"), tuple((x.get("name"), x.get("type")) for x in item.get("inputs", [])))
            if key not in seen_forms:
                seen_forms.add(key); unique_forms.append(item)
        result.forms = unique_forms
        return result

    def run(self, target: str, log=None) -> AnalysisResult:
        target = self._normalize_target(target)
        result = AnalysisResult(target=target)
        root = urlsplit(target)
        queue = [target]
        seen: set[str] = set()
        headers = {"User-Agent": "CTF-Exploit-Workbench/3.0 (Desktop Recon)"}

        with httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            headers=headers,
            verify=False,
        ) as client:
            while queue and len(seen) < self.max_pages:
                url = queue.pop(0)
                url = self._clean_url(url)
                if url in seen or not self._same_origin(root, url):
                    continue
                seen.add(url)

                try:
                    response = client.get(url)
                    final_url = str(response.url)
                    content_type = response.headers.get("content-type", "")
                    body = response.content
                    body_text = response.text[:200000]

                    result.requests.append(RequestRecord(
                        method="GET",
                        status=response.status_code,
                        url=final_url,
                        content_type=content_type,
                        size=len(body),
                        response_body=body_text,
                    ))
                    result.network.append(f"GET {response.status_code} {final_url}")
                    result.site_map.append(final_url)
                    if log:
                        log(f"GET {response.status_code}  {final_url}")

                    # Cookies + technologies + basic secret discovery.
                    for cookie in response.cookies.jar:
                        summary = f"{cookie.name}; domain={cookie.domain or root.netloc}; path={cookie.path or '/'}"
                        if summary not in result.cookies:
                            result.cookies.append(summary)
                    self._detect_technologies(response, body_text, result)
                    self._extract_secrets(body_text, final_url, result)

                    # Discover WebSockets from HTML/JS references and explicit ws URLs.
                    for ws_match in re.findall(r"wss?://[^\s\"'<>]+", body_text, re.I):
                        if ws_match not in result.websockets:
                            result.websockets.append(ws_match)

                    if "text/html" not in content_type.lower():
                        continue

                    soup = BeautifulSoup(body, "html.parser")
                    title = soup.title.get_text(" ", strip=True) if soup.title else ""
                    if title and log:
                        log(f"  title: {title}")
                    self._extract_forms(soup, final_url, result)

                    for script in soup.find_all("script", src=True):
                        script_url = self._clean_url(urljoin(final_url, script.get("src")))
                        if script_url not in result.js_files:
                            result.js_files.append(script_url)

                    # Script inline content can reveal technologies/secrets/ws URLs.
                    for script in soup.find_all("script"):
                        inline = script.string or script.get_text(" ", strip=True)
                        if inline:
                            self._extract_secrets(inline, f"inline:{final_url}", result)
                            for ws_match in re.findall(r"wss?://[^\s\"'<>]+", inline, re.I):
                                if ws_match not in result.websockets:
                                    result.websockets.append(ws_match)

                    self._discover_links(soup, final_url, root, queue, seen)
                except Exception as exc:
                    if log:
                        log(f"ERR     {url}  {exc}")

            self._probe_payloads(client, result, log=log)

        # Deduplicate while preserving order.
        for field_name in ("site_map", "network", "forms", "js_files", "technologies", "cookies", "secrets", "websockets"):
            seq = getattr(result, field_name)
            if field_name == "forms":
                seen_forms = set()
                unique_forms = []
                for item in seq:
                    key = (item.get("method"), item.get("action"), tuple((x.get("name"), x.get("type")) for x in item.get("inputs", [])))
                    if key not in seen_forms:
                        seen_forms.add(key)
                        unique_forms.append(item)
                setattr(result, field_name, unique_forms)
            else:
                setattr(result, field_name, list(dict.fromkeys(seq)))
        return result
