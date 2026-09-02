from __future__ import annotations

import asyncio
import random
import shutil
import subprocess
from typing import Any
from urllib.parse import urlparse

import httpx
from playwright.async_api import Browser, BrowserContext, Page, async_playwright
from core.models import SessionSnapshot


class BrowserSession:
    def __init__(self, target_url: str, logger):
        self.target_url = target_url
        self.logger = logger
        self._pw = None
        self.browser = None
        self.context = None
        self.page = None

    async def start(self):
        self._pw = await async_playwright().start()
        self.browser = await self._pw.chromium.launch(headless=False)
        self.context = await self.browser.new_context(
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
            ),
        )
        self.page = await self.context.new_page()
        await self.page.goto(self.target_url, wait_until="domcontentloaded", timeout=15000)
        self.logger("[browser] Chromium launched and target opened")

    async def capture(self):
        if not self.context or not self.page:
            raise RuntimeError("Browser session is not running")
        cookies = await self.context.cookies()
        local_storage = {}
        origin = f"{urlparse(self.page.url).scheme}://{urlparse(self.page.url).netloc}"
        try:
            values = await self.page.evaluate(
                """() => { const out={}; for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);out[k]=localStorage.getItem(k);} return out; }"""
            )
            local_storage[origin] = values
        except Exception as exc:
            self.logger(f"[session] localStorage unavailable: {exc}")
        return SessionSnapshot(
            cookies=cookies,
            local_storage=local_storage,
            current_url=self.page.url,
            page_html=await self.page.content(),
            page_title=await self.page.title(),
        )

    async def close(self):
        if self.browser:
            await self.browser.close()
        if self._pw:
            await self._pw.stop()
        self.browser = self.context = self.page = self._pw = None


class SessionHttpClient:
    """Session-aware HTTP transport for CTF/lab scanning.

    Strategy:
      1. Prime a persistent Playwright browser context so JavaScript challenges
         (for example /jwt/?i=1 -> JS cookie -> /jwt/?i=2) are actually executed.
      2. Prefer curl/httpx when they work with the primed cookies.
      3. Fall back to the same persistent browser context via context.request,
         which supports headers without abusing Page.goto().

    The browser context is intentionally reused for the whole scan so cookies
    set by JavaScript remain available to subsequent probes.
    """
    def __init__(self, snapshot: SessionSnapshot, timeout=12.0, logger=None):
        self.snapshot = snapshot
        self.logger = logger or (lambda _msg: None)
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
            },
        )
        for cookie in snapshot.cookies:
            try:
                self.client.cookies.set(
                    cookie["name"], cookie["value"], domain=cookie.get("domain"), path=cookie.get("path", "/")
                )
            except Exception:
                self.client.cookies.set(cookie["name"], cookie["value"])
        self._rate_limited = False
        self._browser_pw = None
        self._browser = None
        self._browser_context = None
        self._browser_page = None
        self._browser_primed = False
        self.last_request_snapshot = None

    async def close(self):
        try:
            await self.client.aclose()
        finally:
            try:
                if self._browser_context:
                    await self._browser_context.close()
            finally:
                try:
                    if self._browser:
                        await self._browser.close()
                finally:
                    if self._browser_pw:
                        await self._browser_pw.stop()
            self._browser_page = self._browser_context = self._browser = self._browser_pw = None

    def _cookie_rows(self):
        rows=[]
        for c in self.snapshot.cookies:
            row={
                "name": c.get("name"),
                "value": c.get("value"),
                "path": c.get("path", "/"),
            }
            if c.get("domain"): row["domain"]=c.get("domain")
            if c.get("expires") not in (None, -1): row["expires"]=c.get("expires")
            if c.get("httpOnly") is not None: row["httpOnly"]=c.get("httpOnly")
            if c.get("secure") is not None: row["secure"]=c.get("secure")
            if c.get("sameSite") in {"Strict", "Lax", "None"}: row["sameSite"]=c.get("sameSite")
            if row.get("name") and row.get("value") is not None: rows.append(row)
        return rows

    async def _ensure_browser(self):
        if self._browser_context is not None:
            return self._browser_context
        self._browser_pw = await async_playwright().start()
        self._browser = await self._browser_pw.chromium.launch(headless=True)
        self._browser_context = await self._browser.new_context(
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
            ),
        )
        rows=self._cookie_rows()
        if rows:
            await self._browser_context.add_cookies(rows)
        self._browser_page = await self._browser_context.new_page()
        return self._browser_context

    async def _sync_browser_cookies(self):
        if not self._browser_context:
            return
        cookies = await self._browser_context.cookies()
        self.snapshot.cookies = cookies
        # Keep the httpx/curl cookie jar in sync as well.
        self.client.cookies.clear()
        for c in cookies:
            try:
                self.client.cookies.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))
            except Exception:
                self.client.cookies.set(c["name"], c["value"])

    async def prime_browser_session(self):
        """Execute the target's JavaScript bootstrap/challenge once.

        This is critical for targets whose first response is a JS challenge that
        sets a cookie and redirects to the real application page. A raw curl
        request cannot execute that JavaScript and therefore keeps seeing the
        challenge page.
        """
        if self._browser_primed:
            return
        context = await self._ensure_browser()
        url = self.snapshot.current_url
        if not url:
            raise RuntimeError("Cannot prime browser session: no current target URL")
        page = self._browser_page
        try:
            self.logger(f"[browser] Priming JavaScript/session bootstrap: {url}")
            response = await page.goto(url, wait_until="networkidle", timeout=max(15000, int(self.timeout*1000)))
        except Exception:
            # Some challenge pages never become network-idle; DOM readiness is enough
            # because the challenge's inline script executes during navigation.
            response = await page.goto(url, wait_until="domcontentloaded", timeout=max(15000, int(self.timeout*1000)))
        await self._sync_browser_cookies()
        self.snapshot.current_url = page.url
        try:
            self.snapshot.page_html = await page.content()
            self.snapshot.page_title = await page.title()
        except Exception:
            pass
        cookie_names=sorted(c.get("name","") for c in self.snapshot.cookies if c.get("name"))
        self.logger(
            f"[browser] Session primed -> {page.url} "
            f"({response.status if response else 0}); cookies={', '.join(cookie_names) or 'none'}"
        )
        self._browser_primed = True

    async def _curl_request(self, method: str, url: str, **kwargs: Any):
        if not shutil.which("curl"):
            raise RuntimeError("curl binary is not installed")
        headers = dict(kwargs.pop("headers", {}) or {})
        content = kwargs.pop("content", None)
        timeout = float(kwargs.pop("timeout", self.timeout))
        follow_redirects = bool(kwargs.pop("follow_redirects", True))
        if kwargs:
            raise RuntimeError(f"curl fallback does not support options: {', '.join(kwargs)}")
        try:
            cookie_items = list(self.client.cookies.items())
        except Exception:
            cookie_items = []
        if cookie_items and "Cookie" not in {str(k).title() for k in headers}:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k,v in cookie_items)
        cmd=["curl","--silent","--show-error","--include","--request",method.upper(),"--max-time",str(max(1,int(timeout))),"--compressed"]
        if follow_redirects: cmd.append("--location")
        else: cmd += ["--max-redirs","0"]
        for key,value in headers.items(): cmd += ["--header",f"{key}: {value}"]
        if content is not None:
            data = content if isinstance(content,bytes) else str(content).encode()
            proc=await asyncio.to_thread(subprocess.run, cmd+[url], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        else:
            proc=await asyncio.to_thread(subprocess.run, cmd+[url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.decode("utf-8","replace").strip() or f"curl exit {proc.returncode}")
        raw=proc.stdout
        # Walk the header chain so redirects/challenge responses are parsed safely.
        chunks=raw.split(b"\r\n\r\n")
        if len(chunks)==1: chunks=raw.split(b"\n\n")
        block=chunks[0]
        body=chunks[-1] if len(chunks)>1 else b""
        # If curl followed redirects, the last status block precedes final body.
        for candidate in reversed(chunks[:-1]):
            if candidate.startswith(b"HTTP/"):
                block=candidate; break
        lines=block.splitlines()
        while lines and not lines[0].startswith(b"HTTP/"):
            lines.pop(0)
        if not lines: raise RuntimeError("curl returned no HTTP status line")
        status_line=lines[0].decode("iso-8859-1","replace")
        try: status_code=int(status_line.split()[1])
        except Exception as exc: raise RuntimeError(f"unable to parse curl status line: {status_line!r}") from exc
        headers_out={}
        for line in lines[1:]:
            if b":" not in line: continue
            key,value=line.split(b":",1)
            headers_out[key.decode("iso-8859-1","replace").strip()]=value.decode("iso-8859-1","replace").strip()
        return httpx.Response(status_code,headers=headers_out,content=body,request=httpx.Request(method,url))

    async def _browser_request(self, method: str, url: str, **kwargs: Any):
        context = await self._ensure_browser()
        if not self._browser_primed:
            await self.prime_browser_session()
            context = self._browser_context
        headers=dict(kwargs.get("headers") or {})
        headers.setdefault("Referer", self.snapshot.current_url or url)
        timeout_ms=int(float(kwargs.get("timeout", self.timeout))*1000)
        content=kwargs.get("content", None)
        data=None
        if content is not None:
            data=content if isinstance(content,bytes) else str(content).encode("utf-8","surrogatepass")
        response = await context.request.fetch(
            url,
            method=method.upper(),
            headers=headers,
            data=data,
            timeout=timeout_ms,
            fail_on_status_code=False,
            max_redirects=5,
        )
        body=await response.body()
        hdrs=dict(response.headers)
        # Page.goto can update cookies; APIRequestContext shares the same context,
        # so sync them after every request.
        await self._sync_browser_cookies()
        return httpx.Response(response.status, headers=hdrs, content=body, request=httpx.Request(method,url))

    def _build_request_snapshot(self, method: str, url: str, headers: dict[str, Any] | None, content: Any = None):
        # Preserve browser-like defaults so Scanner -> Repeater gets a faithful
        # replayable request even when a module only supplied URL/body.
        effective = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
        }
        effective.update(dict(headers or {}))
        # Merge the current browser/session cookies into the exact request copy.
        # Explicit Cookie wins if the caller deliberately supplied one.
        if not any(str(k).lower() == "cookie" for k in effective):
            try:
                cookie_items = list(self.client.cookies.items())
            except Exception:
                cookie_items = []
            if cookie_items:
                effective["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookie_items)
        body = content if isinstance(content, bytes) else (str(content).encode("utf-8", "surrogatepass") if content is not None else b"")
        parsed = urlparse(url)
        if not any(str(k).lower() == "host" for k in effective) and parsed.netloc:
            effective["Host"] = parsed.netloc
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        lines = [f"{method.upper()} {target} HTTP/1.1"]
        for key, value in effective.items():
            lines.append(f"{key}: {value}")
        raw = "\n".join(lines) + "\n\n"
        try:
            raw += body.decode("utf-8", "replace")
        except Exception:
            raw += body.decode("latin-1", "replace")
        return {
            "method": method.upper(),
            "url": url,
            "headers": effective,
            "body": body,
            "raw": raw,
        }

    async def request(self, method: str, url: str, **kwargs: Any):
        """Send a request while preserving the JavaScript/browser session."""
        use_curl=bool(kwargs.pop("use_curl", True))
        self.last_request_snapshot = self._build_request_snapshot(
            method, url, kwargs.get("headers"), kwargs.get("content")
        )
        # Prime once up front. This turns the raw /jwt/?i=1 JS challenge into
        # the real browser session before any scanner payload is sent.
        try:
            await self.prime_browser_session()
        except Exception as exc:
            self.logger(f"[!] Browser session priming failed: {exc}")

        if use_curl:
            try:
                self.logger(f"[curl] {method.upper()} {url}")
                response=await self._curl_request(method,url,**dict(kwargs))
                self.logger(f"[curl] {method.upper()} {url} -> {response.status_code}, {len(response.content)} bytes")
            except (httpx.HTTPError,OSError,RuntimeError) as exc:
                self.logger(f"[!] HTTP client error for {url}: {exc}")
                self.logger(f"[~] Browser transport: {method.upper()} {url}")
                response=await self._browser_request(method,url,**dict(kwargs))
                self.logger(f"[browser-fetch] {method.upper()} {url} -> {response.status_code}, {len(response.content)} bytes")
        else:
            try:
                response=await self.client.request(method,url,**kwargs)
            except (httpx.HTTPError,OSError) as exc:
                self.logger(f"[!] httpx error for {url}: {exc}")
                response=await self._browser_request(method,url,**dict(kwargs))
                self.logger(f"[browser-fetch] {method.upper()} {url} -> {response.status_code}, {len(response.content)} bytes")

        # Refresh the replay snapshot after transport, because bootstrap/session
        # cookies may have changed during the request path. Keep the exact headers
        # the module supplied plus the current cookie jar.
        self.last_request_snapshot = self._build_request_snapshot(
            method, url, kwargs.get("headers"), kwargs.get("content")
        )
        last_response=response
        status=response.status_code
        server=(response.headers.get("server") or "").lower()
        body_prefix=""
        try: body_prefix=response.text[:2000].lower()
        except Exception: pass
        is_rate_limit=status==429
        is_transient_block=status in {502,503,504} and "cloudflare" in (server+" "+body_prefix)
        is_js_challenge=("function tonumbers" in body_prefix and "document.cookie" in body_prefix) or "challenge-platform" in body_prefix or "cf-chl-" in body_prefix
        if is_js_challenge and not self._browser_primed:
            self.logger(f"[~] JavaScript challenge detected at {url}; executing browser bootstrap")
            await self.prime_browser_session()
            response=await self._browser_request(method,url,**dict(kwargs))
            self.logger(f"[browser-fetch] {method.upper()} {url} -> {response.status_code}, {len(response.content)} bytes")
        if is_rate_limit or is_transient_block:
            self._rate_limited=True
        return response
