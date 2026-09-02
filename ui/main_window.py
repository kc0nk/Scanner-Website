from __future__ import annotations

import asyncio
import json
import os
import threading
from urllib.parse import urlsplit
from concurrent.futures import Future
from pathlib import Path

from PySide6.QtCore import QThread, Signal, QObject, Slot, Qt, QTimer
from PySide6.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter, QBrush
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QFrame,
    QPlainTextEdit, QPushButton, QSplitter, QStackedWidget, QVBoxLayout, QWidget,
    QTabWidget, QRadioButton, QButtonGroup, QTextEdit, QScrollArea, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QMenu, QTextBrowser
)

from core.engine import ExploitEngine
from core.models import Target
from core.target import validate_target
from modules import ALL_MODULES
from core.payloads import payload_summary, total_payloads


class CtfSyntaxHighlighter(QSyntaxHighlighter):
    """Lightweight code/HTTP syntax highlighting for Repeater and Dashboard editors."""
    def __init__(self, document, mode="http"):
        super().__init__(document)
        self.mode = mode
        self.formats = {}
        for name, color, weight in [
            ("method", "#ff9f43", QFont.Weight.Bold),
            ("status_ok", "#62d9a6", QFont.Weight.Bold),
            ("status_err", "#ff7675", QFont.Weight.Bold),
            ("header", "#61dafb", QFont.Weight.Bold),
            ("url", "#a78bfa", QFont.Weight.Normal),
            ("value", "#e5e7eb", QFont.Weight.Normal),
            ("keyword", "#f472b6", QFont.Weight.Bold),
            ("string", "#f8c471", QFont.Weight.Normal),
            ("number", "#74b9ff", QFont.Weight.Normal),
            ("comment", "#72808f", QFont.Weight.Normal),
            ("tag", "#67e8f9", QFont.Weight.Bold),
            ("attr", "#c084fc", QFont.Weight.Normal),
            ("bracket", "#94a3b8", QFont.Weight.Normal),
        ]:
            f=QTextCharFormat(); f.setForeground(QColor(color)); f.setFontWeight(weight); self.formats[name]=f

    def highlightBlock(self, text):
        if self.mode in ("http", "response", "request"):
            self._highlight_http(text)
        elif self.mode == "json":
            self._highlight_json(text)
        elif self.mode == "html":
            self._highlight_html(text)
        else:
            self._highlight_http(text)

    def _highlight_http(self, text):
        import re
        m=re.match(r"^([A-Z]+)\s+(\S+)(?:\s+(HTTP/\d(?:\.\d)?))?$", text)
        if m:
            self.setFormat(0,len(m.group(1)),self.formats["method"])
            self.setFormat(len(m.group(1))+1,len(m.group(2)),self.formats["url"])
            if m.group(3):
                self.setFormat(text.find(m.group(3)),len(m.group(3)),self.formats["keyword"])
            return
        sm=re.match(r"^(HTTP/\d(?:\.\d)?)\s+(\d{3})(?:\s+(.*))?$", text)
        if sm:
            self.setFormat(0,len(sm.group(1)),self.formats["keyword"])
            code=sm.group(2); cf=self.formats["status_ok"] if code.startswith(("2","3")) else self.formats["status_err"]
            self.setFormat(text.find(code),3,cf)
            if sm.group(3): self.setFormat(text.find(sm.group(3)),len(sm.group(3)),self.formats["value"])
            return
        hm=re.match(r"^([!#$%&'*+.^_`|~0-9A-Za-z-]+):(\s*)(.*)$", text)
        if hm:
            self.setFormat(0,len(hm.group(1))+1,self.formats["header"])
            if hm.group(3):
                start=text.find(hm.group(3)); self.setFormat(start,len(hm.group(3)),self.formats["value"])
                for mat in re.finditer(r"https?://[^\s]+",hm.group(3)):
                    self.setFormat(start+mat.start(),len(mat.group(0)),self.formats["url"])
            return
        if not text.strip(): return
        for mat in re.finditer(r"https?://[^\s'\"]+", text): self.setFormat(mat.start(),len(mat.group(0)),self.formats["url"])
        for mat in re.finditer(r"\b(?:true|false|null|GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|TRACE|CONNECT)\b", text): self.setFormat(mat.start(),len(mat.group(0)),self.formats["keyword"])
        for mat in re.finditer(r"\b\d+(?:\.\d+)?\b", text): self.setFormat(mat.start(),len(mat.group(0)),self.formats["number"])

    def _highlight_json(self, text):
        import re
        for mat in re.finditer(r'"(?:\\.|[^"\\])*"(?=\s*:)', text): self.setFormat(mat.start(),len(mat.group(0)),self.formats["header"])
        for mat in re.finditer(r'"(?:\\.|[^"\\])*"', text):
            if self.currentBlock().charFormat() if False else False: pass
            self.setFormat(mat.start(),len(mat.group(0)),self.formats["string"])
        for mat in re.finditer(r"\b(?:true|false|null)\b", text): self.setFormat(mat.start(),len(mat.group(0)),self.formats["keyword"])
        for mat in re.finditer(r"-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b", text): self.setFormat(mat.start(),len(mat.group(0)),self.formats["number"])
        for mat in re.finditer(r"[{}\[\],:]", text): self.setFormat(mat.start(),1,self.formats["bracket"])

    def _highlight_html(self, text):
        import re
        for mat in re.finditer(r"<!--.*?-->", text): self.setFormat(mat.start(),len(mat.group(0)),self.formats["comment"])
        for mat in re.finditer(r"</?[A-Za-z][^>]*>", text):
            tag=mat.group(0); self.setFormat(mat.start(),len(tag),self.formats["tag"])
            for am in re.finditer(r"\b[A-Za-z_:][-\w:.]*(?=\s*=)", tag): self.setFormat(mat.start()+am.start(),len(am.group(0)),self.formats["attr"])
            for sm in re.finditer(r'"[^"\n]*"|\'[^\'\n]*\'', tag): self.setFormat(mat.start()+sm.start(),len(sm.group(0)),self.formats["string"])


class AsyncWorker(QThread):
    log_message = Signal(str)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            result = asyncio.run(self.fn())
            self.done.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class BrowserWorker(QThread):
    browser_ready = Signal(str)
    navigated = Signal(str)
    network_event = Signal(str)
    request_recorded = Signal(object)
    response_recorded = Signal(object)
    error = Signal(str)
    intercept_recorded = Signal(object)
    repeater_response = Signal(object)
    repeater_error = Signal(str)
    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url
        self.loop = None
        self._ready = threading.Event()
        self._closing = False
        self._nav_history = []
        self._requests = []
        self._responses = []
        self._intercept_enabled = False
        self._intercept_lock = asyncio.Lock()
        self._pending_intercepts = {}
        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
    def run(self):
        asyncio.run(self._main())
    def _record_url(self, url):
        if url and (not self._nav_history or self._nav_history[-1] != url):
            self._nav_history = (self._nav_history + [url])[-100:]
        self.navigated.emit(url)
    def _record_request(self, request):
        # Chromium/Playwright intentionally omits Cookie from Request.headers
        # in some contexts.  Resolve the browser context cookie jar explicitly
        # for the request URL so the Dashboard can display the exact cookies
        # that are in scope for that request.
        asyncio.create_task(self._record_request_async(request))

    async def _record_request_async(self, request):
        try:
            headers = dict(await request.all_headers())
        except Exception:
            headers = dict(request.headers)

        cookie_header = headers.get("cookie", "")
        if not cookie_header and getattr(self, "_context", None):
            try:
                cookies = await self._context.cookies(request.url)
                cookie_header = "; ".join(
                    f"{cookie['name']}={cookie['value']}" for cookie in cookies
                )
            except Exception:
                cookie_header = ""

        if cookie_header:
            headers["cookie"] = cookie_header

        item = {
            "method": request.method,
            "url": request.url,
            "resource_type": request.resource_type,
            "headers": headers,
            "cookies": cookie_header,
            "post_data": request.post_data or "",
        }
        self._requests = (self._requests + [item])[-500:]
        self.request_recorded.emit(item)
        self.network_event.emit(f"[net] {request.method} {request.url}")
    async def _record_response(self, response):
        headers = dict(response.headers or {})
        content_type = headers.get("content-type", "")
        content_length = headers.get("content-length", "")
        length = content_length
        body = b""
        if response.request.resource_type in {"document", "xhr", "fetch"} or "text/html" in content_type.lower() or "application/json" in content_type.lower():
            try:
                body = await response.body()
                if not length:
                    length = str(len(body))
            except Exception:
                body = b""
                if not length:
                    length = ""
        title = ""
        try:
            if response.request.resource_type == "document" and response.frame == self._page.main_frame:
                title = await self._page.title()
        except Exception:
            pass
        try:
            body_text = body.decode("utf-8", errors="replace") if body else ""
        except Exception:
            body_text = ""
        item = {
            "status": response.status,
            "status_text": response.status_text,
            "http_version": "HTTP/1.1",
            "url": response.url,
            "resource_type": response.request.resource_type,
            "content_type": content_type,
            "content_length": length,
            "title": title,
            "headers": dict(headers),
            "body": body,
            "body_text": body_text,
        }
        self._responses = (self._responses + [item])[-500:]
        self.response_recorded.emit(item)
    async def _repeater_request_async(self, method, url, headers=None, body=b""):
        if not self._context:
            raise RuntimeError("Browser context is not ready")
        hdrs = dict(headers or {})
        # Preserve the captured request while also merging the current browser
        # cookie jar.  An explicit Cookie header from an old History entry can
        # otherwise suppress a fresh bootstrap cookie such as __test.
        try:
            jar = await self._context.cookies(url)
            jar_pairs = [(c["name"], c["value"]) for c in jar if c.get("name") and c.get("value") is not None]
            explicit_cookie = None
            for k in list(hdrs):
                if k.lower() == "cookie":
                    explicit_cookie = hdrs[k]
                    del hdrs[k]
                    break
            merged = []
            seen = set()
            if explicit_cookie:
                for part in explicit_cookie.split(";"):
                    if "=" in part:
                        name, value = part.strip().split("=", 1)
                        if name and name not in seen:
                            merged.append((name, value)); seen.add(name)
            for name, value in jar_pairs:
                if name not in seen:
                    merged.append((name, value)); seen.add(name)
            if merged:
                hdrs["Cookie"] = "; ".join(f"{n}={v}" for n, v in merged)
        except Exception:
            pass
        data = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8", "surrogatepass")
        response = await self._context.request.fetch(
            url,
            method=str(method).upper(),
            headers=hdrs,
            data=data if data else None,
            timeout=20000,
            fail_on_status_code=False,
            max_redirects=10,
        )
        response_body = await response.body()
        result = {
            "status": response.status,
            "status_text": response.status_text,
            "url": response.url,
            "http_version": "HTTP/1.1",
            "headers": dict(response.headers),
            "body": response_body,
        }
        try:
            cookies = await self._context.cookies()
            self._sync_request_cookie_jar(cookies)
        except Exception:
            pass
        return result

    def _sync_request_cookie_jar(self, cookies):
        # Keep the browser worker as the authoritative session source. The
        # captured request history receives cookie values separately.
        return cookies

    def send_repeater_request(self, method, url, headers=None, body=b"", tab_index=None):
        if not self.loop or not self.loop.is_running() or not self._context:
            return False
        async def _run():
            try:
                result = await self._repeater_request_async(method, url, headers, body)
                self.repeater_response.emit({"tab_index": tab_index, "result": result})
            except Exception as exc:
                self.repeater_error.emit(str(exc))
        try:
            asyncio.run_coroutine_threadsafe(_run(), self.loop)
            return True
        except Exception as exc:
            self.repeater_error.emit(str(exc))
            return False

    async def _main(self):
        from playwright.async_api import async_playwright
        try:
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(headless=False)
            self._context = await self._browser.new_context(
                viewport={"width": 1440, "height": 900},
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
                ),
            )
            self._page = await self._context.new_page()
            self._page.on("request", self._record_request)
            self._page.on("response", lambda r: asyncio.create_task(self._record_response(r)))
            self._page.on("framenavigated", lambda frame: self._record_url(frame.url) if frame == self._page.main_frame else None)
            await self._page.route("**/*", self._route_handler)
            self.loop = asyncio.get_running_loop()
            self._ready.set()
            await self._page.goto(self.target_url, wait_until="domcontentloaded", timeout=20000)
            self._record_url(self._page.url)
            self.browser_ready.emit(self._page.url)
            while not self._closing:
                await asyncio.sleep(0.25)
        except Exception as exc:
            self._ready.set()
            self.error.emit(str(exc))
        finally:
            try:
                if getattr(self, "_browser", None):
                    await self._browser.close()
                if getattr(self, "_pw", None):
                    await self._pw.stop()
            except Exception:
                pass
    def wait_ready(self, timeout=20):
        return self._ready.wait(timeout)
    def set_intercept(self, enabled):
        enabled = bool(enabled)
        self._intercept_enabled = enabled
        # Turning interception OFF means traffic should immediately return
        # to pass-through mode. Release anything that was already paused so
        # the browser cannot remain stuck on a request after the toggle is off.
        if not enabled and self.loop and self._pending_intercepts:
            async def _release_pending():
                pending = list(self._pending_intercepts.values())
                for _route, future in pending:
                    if not future.done():
                        future.set_result(("forward", None))
            try:
                asyncio.run_coroutine_threadsafe(_release_pending(), self.loop)
            except Exception:
                pass

    async def _route_handler(self, route):
        request = route.request
        if not self._intercept_enabled or request.resource_type not in {"document", "xhr", "fetch", "script", "stylesheet"}:
            await route.continue_()
            return

        loop = asyncio.get_running_loop()
        token = id(route)
        future = loop.create_future()
        self._pending_intercepts[token] = (route, future)
        record = {
            "token": token,
            "method": request.method,
            "url": request.url,
            "headers": dict(request.headers),
            "post_data": request.post_data or "",
            "resource_type": request.resource_type,
        }
        self.intercept_recorded.emit(record)
        try:
            action, edited = await future
            if action == "drop":
                await route.abort()
            else:
                if edited:
                    await route.continue_(**edited)
                else:
                    await route.continue_()
        except Exception:
            try:
                await route.continue_()
            except Exception:
                pass
        finally:
            self._pending_intercepts.pop(token, None)

    def resolve_intercept(self, token, action, edited=None):
        if not self.loop:
            return False
        async def _resolve():
            item = self._pending_intercepts.get(token)
            if not item:
                return False
            route, future = item
            if not future.done():
                future.set_result((action, edited))
            return True
        try:
            return asyncio.run_coroutine_threadsafe(_resolve(), self.loop).result(timeout=3)
        except Exception:
            return False

    async def _capture_async(self):
        from core.models import SessionSnapshot
        from urllib.parse import urlparse
        cookies = await self._context.cookies()
        values = {}
        try:
            values = await self._page.evaluate("""() => { const o={}; for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);o[k]=localStorage.getItem(k);} return o; }""")
        except Exception:
            pass
        u = self._page.url
        parsed = urlparse(u)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        return SessionSnapshot(
            cookies=cookies,
            local_storage={origin: values} if origin else {},
            current_url=u,
            page_html=await self._page.content(),
            page_title=await self._page.title(),
            navigation_history=list(self._nav_history),
            network_requests=list(self._requests),
            network_responses=list(self._responses),
        )
    def capture(self):
        if not self.loop or not self._ready.is_set():
            raise RuntimeError("Browser is not ready")
        return asyncio.run_coroutine_threadsafe(self._capture_async(), self.loop).result(timeout=15)
    def close_browser(self):
        """Request browser shutdown without blocking the Qt GUI thread."""
        self._closing = True
        loop = self.loop
        if not loop or not loop.is_running():
            return
        async def _close_async():
            pending = list(self._pending_intercepts.values())
            for _route, future in pending:
                try:
                    if not future.done():
                        future.set_result(("forward", None))
                except Exception:
                    pass
            self._pending_intercepts.clear()
        try:
            asyncio.run_coroutine_threadsafe(_close_async(), loop)
        except Exception:
            pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CTF Exploit Workbench")
        self.resize(1450, 900)
        self.browser_worker: BrowserWorker | None = None
        self._pending_browser_target = ""
        self._browser_restart_connected = False
        self.snapshot = None
        self.worker = None
        self._repeater_worker = None
        self._repeater_browser_active = False
        self._closing = False
        self.execution_ready = False
        self.execution_capabilities: list[str] = []
        self.target_url = ""
        self._exploit_target = ""
        # Always create the scanner spinner before any worker signal can reach
        # _set_exploitation_running(). This prevents AttributeError during
        # scanner completion/error callbacks.
        self._exploit_spinner = QTimer(self)
        self._exploit_spinner.setInterval(250)
        self._exploit_spinner.timeout.connect(self._update_exploit_spinner)
        self._exploit_spinner_index = 0
        self._shutdown_requested = False
        self._signal_shutdown_requested = False
        self._build_ui()

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        # --- Sidebar / navigation ---
        self.sidebar = QWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(220)
        side_layout = QVBoxLayout(self.sidebar)
        side_layout.setContentsMargins(14, 16, 14, 16)
        side_layout.setSpacing(8)

        top_bar = QHBoxLayout()
        self.menu_toggle = QPushButton("☰")
        self.menu_toggle.setObjectName("menu_toggle")
        self.menu_toggle.setFixedSize(38, 34)
        self.menu_toggle.clicked.connect(self._toggle_sidebar)
        top_bar.addWidget(self.menu_toggle)
        top_bar.addStretch()
        side_layout.addLayout(top_bar)

        self.brand = QLabel("K_C0NK")
        self.brand.setObjectName("brand")
        self.brand.setFont(QFont("Sans Serif", 17, QFont.Weight.Bold))
        side_layout.addWidget(self.brand)

        self.subtitle = QLabel("ZHAFRN DZAKY")
        self.subtitle.setObjectName("sidebar_subtitle")
        side_layout.addWidget(self.subtitle)
        side_layout.addSpacing(18)

        self.nav_dashboard = QPushButton("⌂   Dashboard")
        self.nav_exploitation = QPushButton("⚡  Scanner")
        self.nav_repeater = QPushButton("↻  Repeater")
        self.nav_dashboard.setToolTip("Dashboard")
        self.nav_exploitation.setToolTip("Scanner")
        self.nav_repeater.setToolTip("Repeater")
        for btn in (self.nav_dashboard, self.nav_exploitation, self.nav_repeater):
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            btn.setObjectName("nav_button")
            side_layout.addWidget(btn)

        self.nav_dashboard.clicked.connect(lambda: self._switch_page(0))
        self.nav_exploitation.clicked.connect(lambda: self._switch_page(1))
        self.nav_repeater.clicked.connect(lambda: self._switch_page(2))
        self.nav_dashboard.setChecked(True)

        side_layout.addStretch()
        shell.addWidget(self.sidebar)
        self.sidebar_collapsed = False

        # --- Main content stack ---
        self.pages = QStackedWidget()
        shell.addWidget(self.pages, 1)

        dashboard = self._build_dashboard_page()
        exploitation = self._build_exploitation_page()
        repeater = self._build_repeater_page()
        self.pages.addWidget(dashboard)
        self.pages.addWidget(exploitation)
        self.pages.addWidget(repeater)

        self.setStyleSheet("""
            QMainWindow { background: #0b0f14; color: #e7edf4; }
            QWidget { background: #0b0f14; color: #e7edf4; }
            QDialog, QDialog QWidget { background: #0b0f14; color: #e7edf4; }
            QWidget#sidebar { background: #0a0e13; border-right: 1px solid #1f2935; }
            QLabel#brand { color: #f5f7fa; letter-spacing: 1px; }
            QLabel#sidebar_subtitle { color: #657285; font-size: 10px; font-weight: bold; letter-spacing: 1px; }
            QPushButton#nav_button {
                background: transparent;
                color: #7f8b9d;
                border: 1px solid transparent;
                border-radius: 8px;
                padding: 12px 13px;
                text-align: left;
                font-size: 13px;
                font-weight: 600;
            }
            QPushButton#nav_button:hover { background: #111823; color: #dce5ef; border-color: #1f2b3a; }
            QPushButton#nav_button:checked { background: #132132; color: #65c7ff; border-color: #204564; }
            QWidget#page { background: #0b0f14; }
            QWidget#repeater_page { background: #0b0f14; }
            QTabWidget#repeater_sessions { background: #090e14; border: 0; }
            QTabWidget#repeater_sessions::pane { border: 1px solid #202c39; background: #090e14; }
            QTabWidget#repeater_sessions QTabBar::tab { background: #101720; color: #8391a3; padding: 8px 14px; border: 1px solid #202b38; border-bottom: 0; margin-right: 2px; }
            QTabWidget#repeater_sessions QTabBar::tab:selected { background: #0b1118; color: #eaf3fb; border-bottom: 2px solid #e56a2e; }
            QTabWidget#repeater_sessions QTabBar::tab:hover { background: #131c26; color: #dce6ef; }
            QFrame#repeater_root, QFrame#repeater_panel, QFrame#repeater_response_panel, QFrame#inspector_panel { background: #090e14; }
            QSplitter#repeater_splitter { background: #090e14; }
            QTabWidget { background: #090e14; }
            QTabWidget::pane { background: #090e14; }
            QStackedWidget { background: #0b0f14; }
            QLabel#page_title { font-size: 28px; font-weight: 700; color: #f4f7fb; }
            QLabel#hero_title { font-size: 22px; font-weight: 700; color: #f4f7fb; }
            QPushButton#menu_toggle { background: transparent; color: #7f8b9d; border: 1px solid transparent; border-radius: 7px; font-size: 17px; }
            QPushButton#menu_toggle:hover { background: #111823; color: #dce5ef; border-color: #1f2b3a; }
            QLabel#page_kicker { color: #5d6b7d; font-size: 11px; font-weight: bold; letter-spacing: 1px; }
            QLineEdit#dashboard_url { background: #0c1219; border: 1px solid #263344; border-radius: 8px; padding: 14px 16px; min-height: 22px; font-size: 14px; }
            QLineEdit#dashboard_url:focus { border-color: #2d83c7; }
            QPushButton#dashboard_submit { background: #1b78bb; border-radius: 8px; padding: 12px 18px; min-height: 26px; }
            QPushButton#exploit_button { background: #b64a22; border-radius: 8px; padding: 14px 22px; min-height: 32px; font-size: 15px; font-weight: 800; }
            QPushButton#exploit_button:hover { background: #d45c2b; }
            QPushButton#exploit_button:pressed { background: #963d1d; }
            QPlainTextEdit#http_editor { background: #080d13; border: 1px solid #263344; border-radius: 8px; color: #d7e0ea; font-family: monospace; font-size: 13px; padding: 12px; }
            QTableWidget#intruder_table { background: #0b1016; alternate-background-color: #0e141b; gridline-color: #1d2732; border: 1px solid #202b39; border-radius: 8px; color: #d6dee8; selection-background-color: #16324a; }
            QLabel#panel_label { color: #91a0b3; font-size: 12px; font-weight: 700; }
            QLabel#exploit_output_status { color: #55c7ff; background: #0c1219; border: 1px solid #263344; border-radius: 6px; padding: 5px 9px; font-size: 11px; font-weight: 800; }
            QPlainTextEdit#exploit_output { background: #080d13; border: 1px solid #263344; border-radius: 8px; color: #c7d2df; font-family: monospace; font-size: 13px; padding: 12px; }
            QLabel#exploit_status { color: #657285; font-size: 12px; }
            QPushButton#dashboard_submit:hover { background: #2490d6; }

            QPushButton#repeater_send { background: #e56a2e; color: #fff; border: 0; border-radius: 6px; padding: 8px 18px; font-size: 14px; font-weight: 700; }
            QPushButton#repeater_send:hover { background: #f07a3c; }
            QPushButton#repeater_tool { background: #151c24; color: #b8c4d2; border: 1px solid #293545; border-radius: 6px; padding: 7px 10px; }
            QLabel#repeater_target { color: #8d9bad; font-size: 11px; }
            QTabWidget#repeater_tabs::pane { border: 1px solid #243140; background: #090e14; }
            QTabWidget#repeater_tabs QTabBar::tab { background: #101720; color: #8391a3; padding: 9px 14px; border: 0; }
            QTabWidget#repeater_tabs QTabBar::tab:selected { color: #eaf3fb; background: #0b1118; border-bottom: 2px solid #e56a2e; }
            QPlainTextEdit#jwt_editor { background: #080d13; border: 0; color: #dce6f0; font-family: monospace; font-size: 12px; padding: 8px; }
            QFrame#repeater_panel { background: #090e14; border: 1px solid #202c39; }
            QFrame#inspector_panel { background: #0b1118; border-left: 1px solid #202c39; }
            QPushButton#inspector_row { background: transparent; color: #8c99aa; border: 0; text-align: left; padding: 9px 4px; font-size: 12px; }
            QPushButton#inspector_row:hover { color: #dbe6ef; background: #111a24; }
            QLabel#dashboard_status { color: #657285; font-size: 12px; padding-left: 2px; }
            QFrame#history_frame { background: #0b1016; border: 1px solid #202b39; border-radius: 8px; }
            QTableWidget#request_table { background: #0b1016; alternate-background-color: #0e141b; gridline-color: #1d2732; border: 0; border-radius: 8px; color: #d6dee8; selection-background-color: #16324a; selection-color: #ffffff; }
            QTableWidget#request_table::item { padding: 5px 7px; }
            QHeaderView::section { background: #111823; color: #91a0b3; padding: 6px 7px; border: 0; border-right: 1px solid #202b39; border-bottom: 1px solid #202b39; font-size: 11px; font-weight: 600; }
            QLabel#hero { color: #aeb9c8; font-size: 14px; line-height: 1.5; }
            QFrame#hero_card, QFrame#info_card {
                background: #10161e;
                border: 1px solid #202c3a;
                border-radius: 12px;
            }
            QLabel#card_title { color: #e9eef5; font-size: 14px; font-weight: 700; }
            QLabel#card_text { color: #758296; font-size: 12px; }
            QGroupBox { border: 1px solid #253142; border-radius: 9px; margin-top: 10px; padding: 10px; background: #0f151d; }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 5px; color: #91a0b3; }
            QLineEdit, QPlainTextEdit, QListWidget { background: #0c1219; border: 1px solid #263344; border-radius: 7px; padding: 8px; }
            QLineEdit:focus, QPlainTextEdit:focus, QListWidget:focus { border-color: #2d83c7; }
            QMenu#text_context_menu { background: #0b0f14; color: #f1f5f9; border: 1px solid #273445; padding: 5px 0; font-size: 13px; }
            QMenu#text_context_menu::item { background: transparent; color: #f1f5f9; padding: 8px 18px; margin: 1px 4px; border-radius: 4px; }
            QMenu#text_context_menu::item:selected { background: #162436; color: #ffffff; }
            QMenu#text_context_menu::separator { height: 1px; background: #273445; margin: 5px 8px; }
            QComboBox { background: #0c1219; color: #e7edf4; border: 1px solid #263344; border-radius: 7px; padding: 8px 10px; min-height: 18px; }
            QComboBox:hover { border-color: #35506a; }
            QComboBox:focus { border-color: #2d83c7; }
            QComboBox::drop-down { border: 0; width: 28px; }
            QComboBox QAbstractItemView { background: #0c1219; color: #e7edf4; border: 1px solid #263344; selection-background-color: #16324a; selection-color: #ffffff; }
            QPushButton { background: #1768a8; border: 0; border-radius: 7px; padding: 10px 14px; font-weight: 700; }
            QPushButton:hover { background: #2081ca; }
            QSplitter::handle { background: #151e29; }
            QScrollBar:vertical, QScrollBar:horizontal { background: #090e14; border: 0; }
            QScrollBar::handle:vertical, QScrollBar::handle:horizontal { background: #263344; border-radius: 5px; min-height: 28px; min-width: 28px; }
            QScrollBar::add-line, QScrollBar::sub-line { background: #090e14; border: 0; }
            QLabel[side="true"] { padding: 10px; color: #aeb7c4; }
            QWidget#terminal_frame { background: #05080b; border: 1px solid #1f2c3a; border-radius: 10px; }
            QPlainTextEdit#terminal_view { background: #05080b; border: 0; color: #c9d5e3; padding: 12px; }
            QLabel#terminal_prompt { color: #55c7ff; font-family: monospace; font-weight: 700; }
        """)

    def _build_dashboard_page(self):
        """Clean dashboard with a single target URL entry point."""
        page = QWidget()
        page.setObjectName("page")
        content = QVBoxLayout(page)
        content.setContentsMargins(34, 30, 34, 30)
        content.setSpacing(18)

        kicker = QLabel("CTF / WEB EXPLOITATION")
        kicker.setObjectName("page_kicker")
        title = QLabel("Dashboard")
        title.setObjectName("page_title")
        content.addWidget(kicker)
        content.addWidget(title)

        target_row = QHBoxLayout()
        target_row.setSpacing(10)

        self.dashboard_url = QLineEdit()
        self.dashboard_url.setObjectName("dashboard_url")
        self.dashboard_url.setPlaceholderText("Enter target URL...")
        self._install_text_context_menu(self.dashboard_url)
        self.dashboard_url.setText("http://127.0.0.1:8080")
        self.dashboard_url.returnPressed.connect(self._submit_dashboard_url)

        self.dashboard_submit = QPushButton("SUBMIT")
        self.dashboard_submit.setObjectName("dashboard_submit")
        self.dashboard_submit.setMinimumWidth(120)
        self.dashboard_submit.clicked.connect(self._submit_dashboard_url)

        target_row.addWidget(self.dashboard_url, 1)
        target_row.addWidget(self.dashboard_submit)
        content.addLayout(target_row)

        self.dashboard_status = QLabel("No target submitted")
        self.dashboard_status.setObjectName("dashboard_status")
        content.addWidget(self.dashboard_status)

        # Burp-like HTTP history table directly beneath the target URL field.
        history_frame = QFrame()
        history_frame.setObjectName("history_frame")
        history_layout = QVBoxLayout(history_frame)
        history_layout.setContentsMargins(0, 0, 0, 0)
        history_layout.setSpacing(0)

        self.request_table = QTableWidget(0, 15)
        self.request_table.setObjectName("request_table")
        self.request_table.setHorizontalHeaderLabels([
            "#", "Host", "Method", "URL", "Params", "Cookies", "Edited", "Status code",
            "Length", "MIME type", "Extension", "Title", "Notes", "TLS", "IP"
        ])
        self.request_table.setAlternatingRowColors(True)
        self.request_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.request_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.request_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.request_table.customContextMenuRequested.connect(self._show_request_context_menu)
        self.request_table.verticalHeader().setVisible(False)
        header = self.request_table.horizontalHeader()
        # Dashboard request columns are user-resizable (drag the header divider).
        # Keep only the row number content-sized; all useful fields can be widened
        # or narrowed independently, including URL and Params.
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        for idx in range(1, 15):
            header.setSectionResizeMode(idx, QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(False)
        self.request_table.setMinimumHeight(250)
        history_layout.addWidget(self.request_table)
        content.addWidget(history_frame, 1)
        detail=QSplitter(Qt.Orientation.Horizontal)
        rf=QFrame(); rv=QVBoxLayout(rf); rv.addWidget(QLabel("Selected Request")); self.dashboard_request_preview=QPlainTextEdit(); self.dashboard_request_preview.setReadOnly(True); rv.addWidget(self.dashboard_request_preview)
        sf=QFrame(); sv=QVBoxLayout(sf); sv.addWidget(QLabel("Selected Response"))
        self.dashboard_response_tabs=QTabWidget(); self.dashboard_response_preview=QPlainTextEdit(); self.dashboard_response_preview.setReadOnly(True)
        self.dashboard_response_render=QTextBrowser(); self.dashboard_response_render.setOpenExternalLinks(False); self.dashboard_response_render.setOpenLinks(False)
        self.dashboard_response_pretty=QPlainTextEdit(); self.dashboard_response_pretty.setReadOnly(True); self._attach_code_highlighter(self.dashboard_response_pretty,"response")
        self._attach_code_highlighter(self.dashboard_response_preview,"http")
        self.dashboard_response_tabs.addTab(self.dashboard_response_pretty, "Pretty")
        self.dashboard_response_tabs.addTab(self.dashboard_response_preview, "Raw")
        self.dashboard_response_tabs.addTab(self.dashboard_response_render, "Render")
        sv.addWidget(self.dashboard_response_tabs)
        detail.addWidget(rf); detail.addWidget(sf); detail.setMinimumHeight(250); content.addWidget(detail)
        self.request_table.itemSelectionChanged.connect(self._dashboard_selection_changed)
        return page

    def _dashboard_selection_changed(self):
        row=self.request_table.currentRow()
        if row<0: return
        cell=self.request_table.item(row,0); captured=cell.data(Qt.ItemDataRole.UserRole) if cell else None
        if not isinstance(captured,dict): return
        method=captured.get("method","GET"); url=captured.get("url",""); headers=captured.get("headers") or {}; body=captured.get("post_data") or ""
        p=urlsplit(url); path=p.path or "/"; path += ("?"+p.query) if p.query else ""
        self.dashboard_request_preview.setPlainText(f"{method} {path} HTTP/1.1\n"+"\n".join(f"{k}: {v}" for k,v in headers.items())+"\n\n"+body)
        matches=[x for x in getattr(self,"_response_cache",[]) if x.get("url")==url]
        if not matches:
            rp=urlsplit(url)
            for candidate in reversed(getattr(self,"_response_cache",[])):
                cp=urlsplit(candidate.get("url", ""))
                if cp.scheme == rp.scheme and cp.netloc == rp.netloc and (cp.path or "/") == (rp.path or "/"):
                    matches=[candidate]; break
        if matches:
            r=matches[-1]
            status_line = f"{r.get('http_version','HTTP/1.1')} {r.get('status',0)} {r.get('status_text','')}".rstrip()
            raw = status_line + "\n" + "\n".join(f"{k}: {v}" for k,v in (r.get('headers') or {}).items()) + "\n\n" + (r.get('body_text') or "")
            ctype=r.get('content_type') or ""
            pretty_body=self._pretty_body(r.get('body_text') or "", ctype)
            pretty_raw=status_line + "\n" + "\n".join(f"{k}: {v}" for k,v in (r.get('headers') or {}).items()) + "\n\n" + pretty_body
            self.dashboard_response_pretty.setPlainText(pretty_raw)
            self.dashboard_response_preview.setPlainText(raw)
            if ctype.lower().startswith('text/html'):
                self.dashboard_response_render.setHtml(r.get('body_text') or '')
            else:
                self.dashboard_response_render.setPlainText(r.get('body_text') or '(non-HTML response)')
        else:
            self.dashboard_response_preview.setPlainText("Response not captured yet.")
            self.dashboard_response_render.setPlainText("Response not captured yet.")

    def _request_row_data(self):
        row = self.request_table.currentRow()
        if row < 0:
            return None
        values = {}
        headers = [self.request_table.horizontalHeaderItem(i).text() for i in range(self.request_table.columnCount())]
        for i, header in enumerate(headers):
            item = self.request_table.item(row, i)
            values[header] = item.text() if item else ""
        return values

    def _install_text_context_menu(self, widget):
        """Use a dark, app-local context menu for text inputs/editors.

        The menu is implemented with Qt and only affects this application.
        It does not change the desktop/OS context menu theme.
        """
        widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        widget.customContextMenuRequested.connect(
            lambda pos, w=widget: self._show_text_context_menu(w, pos)
        )

    def _show_text_context_menu(self, widget, pos):
        menu = QMenu(widget)
        menu.setObjectName("text_context_menu")

        is_line = isinstance(widget, QLineEdit)
        is_plain = isinstance(widget, QPlainTextEdit)
        if not (is_line or is_plain):
            return

        if is_line:
            has_selection = bool(widget.selectedText())
            read_only = widget.isReadOnly()
            can_undo = widget.isUndoAvailable()
            can_redo = widget.isRedoAvailable()
            has_focus = widget.hasFocus()
            can_paste = not read_only and bool(QApplication.clipboard().text())

            undo = menu.addAction("↶  Undo")
            undo.setEnabled(can_undo)
            undo.setShortcut("Ctrl+Z")
            redo = menu.addAction("↷  Redo")
            redo.setEnabled(can_redo)
            redo.setShortcut("Ctrl+Shift+Z")
            menu.addSeparator()
            cut = menu.addAction("✂  Cut")
            cut.setEnabled(has_selection and not read_only and has_focus)
            cut.setShortcut("Ctrl+X")
            copy = menu.addAction("▣  Copy")
            copy.setEnabled(has_selection)
            copy.setShortcut("Ctrl+C")
            paste = menu.addAction("▣  Paste")
            paste.setEnabled(can_paste)
            paste.setShortcut("Ctrl+V")
            delete = menu.addAction("⊗  Delete")
            delete.setEnabled(has_selection and not read_only)
            menu.addSeparator()
            select_all = menu.addAction("▣  Select All")
            select_all.setEnabled(bool(widget.text()))
            select_all.setShortcut("Ctrl+A")
        else:
            cursor = widget.textCursor()
            has_selection = cursor.hasSelection()
            read_only = widget.isReadOnly()
            can_undo = widget.document().isUndoAvailable()
            can_redo = widget.document().isRedoAvailable()
            can_paste = not read_only and bool(QApplication.clipboard().text())

            undo = menu.addAction("↶  Undo")
            undo.setEnabled(can_undo)
            undo.setShortcut("Ctrl+Z")
            redo = menu.addAction("↷  Redo")
            redo.setEnabled(can_redo)
            redo.setShortcut("Ctrl+Shift+Z")
            menu.addSeparator()
            cut = menu.addAction("✂  Cut")
            cut.setEnabled(has_selection and not read_only)
            cut.setShortcut("Ctrl+X")
            copy = menu.addAction("▣  Copy")
            copy.setEnabled(has_selection)
            copy.setShortcut("Ctrl+C")
            paste = menu.addAction("▣  Paste")
            paste.setEnabled(can_paste)
            paste.setShortcut("Ctrl+V")
            delete = menu.addAction("⊗  Delete")
            delete.setEnabled(has_selection and not read_only)
            menu.addSeparator()
            select_all = menu.addAction("▣  Select All")
            select_all.setEnabled(bool(widget.toPlainText()))
            select_all.setShortcut("Ctrl+A")

        chosen = menu.exec(widget.mapToGlobal(pos))
        if chosen is None:
            return
        if chosen == undo:
            widget.undo()
        elif chosen == redo:
            widget.redo()
        elif chosen == cut:
            widget.cut()
        elif chosen == copy:
            widget.copy()
        elif chosen == paste:
            widget.paste()
        elif chosen == delete:
            if is_line:
                widget.del_()
            else:
                widget.textCursor().clearSelection()
                cursor = widget.textCursor()
                cursor.deletePreviousChar()
                widget.setTextCursor(cursor)
        elif chosen == select_all:
            widget.selectAll()

    def _show_request_context_menu(self, pos):
        item = self.request_table.itemAt(pos)
        if item is None:
            return
        self.request_table.selectRow(item.row())
        data = self._request_row_data()
        if not data:
            return

        menu = QMenu(self)
        menu.setObjectName("request_context_menu")
        menu.setStyleSheet("""
            QMenu#request_context_menu {
                background: #0b0f14;
                color: #f1f5f9;
                border: 1px solid #273445;
                padding: 5px 0;
                font-size: 13px;
            }
            QMenu#request_context_menu::item {
                background: transparent;
                color: #f1f5f9;
                padding: 8px 18px;
                margin: 1px 4px;
                border-radius: 4px;
            }
            QMenu#request_context_menu::item:selected {
                background: #162436;
                color: #ffffff;
            }
        """)

        # Keep the request history context menu intentionally minimal.
        delete = menu.addAction("Delete item")
        clear = menu.addAction("Clear history")
        menu.addSeparator()
        copy_url = menu.addAction("Copy URL")
        copy_item = menu.addAction("Copy item")
        menu.addSeparator()
        send_repeater = menu.addAction("Send to Repeater")

        chosen = menu.exec(self.request_table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen == delete:
            self.request_table.removeRow(item.row())
            self._renumber_request_table()
            self._append_terminal_line("[history] request removed")
        elif chosen == clear:
            self.request_table.setRowCount(0)
            self._append_terminal_line("[history] cleared")
        elif chosen == copy_url:
            url = self._full_request_url(data)
            QApplication.clipboard().setText(url)
            self._append_terminal_line(f"[clipboard] URL copied: {url}")
        elif chosen == copy_item:
            headers = [self.request_table.horizontalHeaderItem(i).text() for i in range(self.request_table.columnCount())]
            values = [data.get(header, "") for header in headers]
            item_text = "\t".join(values)
            QApplication.clipboard().setText(item_text)
            self._append_terminal_line("[clipboard] request item copied")
        elif chosen == send_repeater:
            self._send_history_item_to_repeater(data)

    def _send_history_item_to_repeater(self, data):
        # Prefer the exact captured browser request. This preserves the same
        # request semantics Burp-style history expects: method, target path,
        # headers, cookies and body. Fall back to the table representation.
        current_row = self.request_table.currentRow()
        captured = None
        if current_row >= 0:
            first = self.request_table.item(current_row, 0)
            if first is not None:
                captured = first.data(Qt.ItemDataRole.UserRole)
        method = (captured or {}).get("method") or data.get("Method", "GET") or "GET"
        url = (captured or {}).get("url") or self._full_request_url(data)
        headers = dict((captured or {}).get("headers") or {})
        if not headers.get("Host") and not headers.get("host"):
            host = urlsplit(url).netloc
            if host:
                headers["Host"] = host
        body = (captured or {}).get("post_data") or ""

        # Never copy hop-by-hop headers that a browser/network stack will
        # regenerate. Everything else remains editable in Repeater.
        for name in list(headers):
            if name.lower() in {"content-length", "transfer-encoding", "connection"}:
                headers.pop(name, None)
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        lines = [f"{method} {path} HTTP/1.1"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        raw = "\n".join(lines) + "\n\n" + body
        st=self._new_repeater_tab(raw=raw,title=f"{method} {urlsplit(url).path or '/'}")
        st["url"]=url; st["target"].setText(f"Target: {urlsplit(url).scheme}://{urlsplit(url).netloc}")
        self.pages.setCurrentIndex(2); self.nav_repeater.setChecked(True); self._sync_repeater_views(); self._append_terminal_line(f"[repeater] opened new tab for {method} {url}")

    def _full_request_url(self, data):
        host = data.get("Host", "")
        path = data.get("URL", "/") or "/"
        scheme = "https" if data.get("TLS") == "✓" else "http"
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{scheme}://{host}{path}" if host else path

    def _renumber_request_table(self):
        for row in range(self.request_table.rowCount()):
            self.request_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))

    def _open_request_url(self, data):
        import webbrowser
        url = self._full_request_url(data)
        webbrowser.open(url)
        self._append_terminal_line(f"[browser] opened: {url}")

    def _submit_dashboard_url(self):
        url = self.dashboard_url.text().strip()
        if not url:
            self.dashboard_status.setText("Enter a target URL")
            return
        ok, reason = validate_target(url)
        if not ok:
            self.dashboard_status.setText(reason)
            QMessageBox.warning(self, "Target blocked", reason)
            return
        self.target_url = url
        self.dashboard_status.setText(f"Target loaded: {url}")
        self._append_terminal_line(f"[target] {url}")
        self.open_browser()

    def _append_terminal_line(self, text):
        if hasattr(self, "terminal_view"):
            self.terminal_view.appendPlainText(text)

    def _build_terminal_page(self):
        """Dedicated terminal UI; exploitation logs are mirrored here."""
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        kicker = QLabel("CTF / WEB EXPLOITATION")
        kicker.setObjectName("page_kicker")
        title = QLabel("Terminal")
        title.setObjectName("page_title")
        layout.addWidget(kicker)
        layout.addWidget(title)

        terminal_frame = QWidget()
        terminal_frame.setObjectName("terminal_frame")
        tf = QVBoxLayout(terminal_frame)
        tf.setContentsMargins(12, 12, 12, 12)
        tf.setSpacing(8)

        self.terminal_view = QPlainTextEdit()
        self.terminal_view.setReadOnly(True)
        self.terminal_view.setObjectName("terminal_view")
        self.terminal_view.setStyleSheet("font-family: monospace; font-size: 13px;")
        self._install_text_context_menu(self.terminal_view)
        self.terminal_view.setPlainText(
            "CTF//WORKBENCH terminal\n"
            "Type commands for the current analysis session.\n\n"
            "ctf@workbench:~$ _"
        )
        tf.addWidget(self.terminal_view, 1)

        cmd_row = QHBoxLayout()
        prompt = QLabel("ctf@workbench:~$")
        prompt.setObjectName("terminal_prompt")
        self.terminal_input = QLineEdit()
        self._install_text_context_menu(self.terminal_input)
        self.terminal_input.setPlaceholderText("Enter a command...")
        self.terminal_input.returnPressed.connect(self._terminal_command)
        self.terminal_run_button = QPushButton("RUN")
        self.terminal_run_button.clicked.connect(self._terminal_command)
        self.terminal_run_button.setEnabled(False)
        self.terminal_run_button.setToolTip("Disabled until the exploitation workflow discovers an execution-capable path (e.g. SSTI/RCE/upload).")
        cmd_row.addWidget(prompt)
        cmd_row.addWidget(self.terminal_input, 1)
        cmd_row.addWidget(self.terminal_run_button)
        tf.addLayout(cmd_row)
        self.terminal_gate_status = QLabel("Execution locked — waiting for a confirmed/potential execution path.")
        self.terminal_gate_status.setObjectName("terminal_gate_status")
        tf.addWidget(self.terminal_gate_status)

        layout.addWidget(terminal_frame, 1)
        return page

    def _build_exploitation_page(self):
        """Empty scanner shell for v3.45. Scanner payloads/commands are removed for rebuild."""
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(12)

        kicker = QLabel("CTF / WEB EXPLOITATION")
        kicker.setObjectName("page_kicker")
        title = QLabel("Scanner")
        title.setObjectName("page_title")
        layout.addWidget(kicker)
        layout.addWidget(title)

        empty = QFrame()
        empty.setObjectName("hero_card")
        ev = QVBoxLayout(empty)
        ev.setContentsMargins(20, 20, 20, 20)
        ev.addStretch(1)
        msg = QLabel("Scanner workspace is empty in v3.45.0")
        msg.setObjectName("hero_title")
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ev.addWidget(msg)
        detail = QLabel("Payloads, exploit commands, Terminal, and Intruder have been removed for the scanner rebuild.")
        detail.setObjectName("exploit_status")
        detail.setAlignment(Qt.AlignmentFlag.AlignCenter)
        detail.setWordWrap(True)
        ev.addWidget(detail)
        ev.addStretch(1)
        layout.addWidget(empty, 1)
        return page

    def _add_finding(self, url, payload, vuln, response, repeater_raw=None, finding_meta=None):
        """Display one aggregated, exploit-verified vulnerability.

        The table is a summary. Full methodology, payload set, request snapshot,
        and verification evidence remain attached to the row for Repeater/actions.
        """
        meta = dict(finding_meta or {})
        for row in range(self.findings_table.rowCount()):
            existing = self._finding_row_data(row)
            if existing and (existing.get("url"), existing.get("vulnerability")) == (str(url), str(vuln)):
                payload_text = existing.get("payload", "")
                if str(payload) and str(payload) not in payload_text:
                    payload_text = (payload_text + " | " + str(payload)).strip(" |")
                    self.findings_table.item(row, 2).setText(payload_text)
                if response:
                    self.findings_table.item(row, 4).setText(str(response))
                verification = meta.get("verification") or existing.get("verification") or "Verified exploit evidence"
                self.findings_table.item(row, 5).setText(str(verification))
                action_item = self.findings_table.item(row, 6)
                if action_item:
                    action_item.setData(Qt.ItemDataRole.UserRole, {"raw": repeater_raw or existing.get("raw", ""), **meta})
                return

        row = self.findings_table.rowCount()
        self.findings_table.insertRow(row)
        verification = meta.get("verification") or "Verified exploit evidence"
        vals = [str(row + 1), str(url), str(payload), str(vuln), str(response), str(verification), "RIGHT-CLICK"]
        for c, v in enumerate(vals):
            self.findings_table.setItem(row, c, QTableWidgetItem(v))
        action_item = self.findings_table.item(row, 6)
        action_item.setData(Qt.ItemDataRole.UserRole, {"raw": repeater_raw or "", **meta})
        action_item.setToolTip("Verified exploit request; right-click to replay in Repeater. Double-click row for methodology.")
        is_rce = any(x in str(vuln).lower() for x in ("rce", "command injection", "remote code execution"))
        action_item.setText("TERMINAL" if is_rce else "REPEATER")
        self.findings_table.selectRow(row)
        self.findings_table.scrollToItem(self.findings_table.item(row, 0))
        count = self.findings_table.rowCount()
        self.scan_terminal_hint.setText(f"{count} verified finding(s) shown • right-click for actions")

    def _finding_row_data(self, row):
        if row < 0:
            return None
        vals = []
        for c in range(self.findings_table.columnCount()):
            item = self.findings_table.item(row, c)
            vals.append(item.text() if item else "")
        meta_item = self.findings_table.item(row, 6)
        meta = meta_item.data(Qt.ItemDataRole.UserRole) if meta_item else {}
        if not isinstance(meta, dict):
            meta = {"raw": meta or ""}
        return {
            "index": row + 1,
            "url": vals[1] if len(vals) > 1 else "",
            "payload": vals[2] if len(vals) > 2 else "",
            "vulnerability": vals[3] if len(vals) > 3 else "",
            "response": vals[4] if len(vals) > 4 else "",
            "verification": vals[5] if len(vals) > 5 else "",
            **meta,
        }

    def _show_finding_details(self, row, _column):
        finding = self._finding_row_data(row)
        if not finding:
            return
        from PySide6.QtWidgets import QDialog, QDialogButtonBox
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Verified Exploit #{finding['index']} — {finding['vulnerability']}")
        dlg.resize(900, 650)
        lay = QVBoxLayout(dlg)
        view = QPlainTextEdit(); view.setReadOnly(True)
        lines = [
            f"Vulnerability : {finding.get('vulnerability','')}",
            f"URL           : {finding.get('url','')}",
            f"Payload(s)    : {finding.get('payloads') or finding.get('payload','')}",
            f"Parameter     : {finding.get('parameter','')}",
            f"Verification  : {finding.get('verification','')}",
            f"Methodology   : {finding.get('methodology','')}",
            "",
            "Response / Evidence:",
            str(finding.get('response','')),
            "",
            "Request snapshot:",
            str(finding.get('raw','') or finding.get('request_raw','')),
        ]
        view.setPlainText("\n".join(lines))
        lay.addWidget(view, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dlg.reject)
        lay.addWidget(buttons)
        dlg.exec()

    def _show_finding_context_menu(self, pos):
        item = self.findings_table.itemAt(pos)
        if item is None:
            return
        row = item.row()
        self.findings_table.selectRow(row)
        finding = self._finding_row_data(row)
        if not finding:
            return

        menu = QMenu(self)
        menu.setObjectName("request_context_menu")
        menu.setStyleSheet("""
            QMenu#request_context_menu {
                background: #0b0f14; color: #f1f5f9; border: 1px solid #273445;
                padding: 5px 0; font-size: 13px;
            }
            QMenu#request_context_menu::item {
                background: transparent; color: #f1f5f9; padding: 8px 18px;
                margin: 1px 4px; border-radius: 4px;
            }
            QMenu#request_context_menu::item:selected { background: #162436; color: #ffffff; }
        """)

        vuln = finding["vulnerability"].lower()
        is_rce = "rce" in vuln or "command injection" in vuln or "remote code execution" in vuln

        primary = menu.addAction("Open in Terminal" if is_rce else "Send to Repeater")
        menu.addSeparator()
        copy_url = menu.addAction("Copy URL")
        copy_payload = menu.addAction("Copy Payload")
        copy_finding = menu.addAction("Copy Finding")

        chosen = menu.exec(self.findings_table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen == primary:
            if is_rce:
                self._send_finding_to_terminal(finding)
            else:
                self._send_finding_to_repeater(finding)
        elif chosen == copy_url:
            QApplication.clipboard().setText(finding["url"])
            self._append_terminal_line("[clipboard] finding URL copied")
        elif chosen == copy_payload:
            QApplication.clipboard().setText(finding["payload"])
            self._append_terminal_line("[clipboard] finding payload copied")
        elif chosen == copy_finding:
            text = f"{finding['url']} | {finding['payload']} | {finding['vulnerability']} | {finding['response']} | {finding.get('verification', '')}"
            QApplication.clipboard().setText(text)
            self._append_terminal_line("[clipboard] finding copied")

    def _send_finding_to_repeater(self, finding=None):
        if isinstance(finding, dict):
            data = finding
        else:
            row = self.findings_table.currentRow()
            data = self._finding_row_data(row)
        if not data:
            return
        raw = data.get("raw", "") or data.get("request_raw", "")
        url = data.get("url", "")
        # A scanner finding is only useful in Repeater when we preserve the
        # request that actually produced the evidence. Never silently reduce
        # the finding to GET + Host. First try the structured session/network
        # history, then the stored raw snapshot.
        if not raw and url:
            try:
                parsed_url = urlsplit(url)
                candidates = []
                if getattr(self, "browser_worker", None) is not None:
                    candidates = list(getattr(self.browser_worker, "_requests", []) or [])
                if not candidates and getattr(self, "snapshot", None) is not None:
                    candidates = list(getattr(self.snapshot, "network_requests", []) or [])
                matching = [r for r in candidates if str(r.get("url", "")).split("#",1)[0] == str(url).split("#",1)[0]]
                source = matching[-1] if matching else (candidates[-1] if candidates else None)
                if source:
                    method = str(source.get("method") or "GET").upper()
                    request_url = str(source.get("url") or url)
                    path = urlsplit(request_url).path or "/"
                    if urlsplit(request_url).query:
                        path += "?" + urlsplit(request_url).query
                    headers = dict(source.get("headers") or {})
                    if not any(str(k).lower() == "host" for k in headers):
                        headers["Host"] = urlsplit(request_url).netloc
                    lines = [f"{method} {path} HTTP/1.1"] + [f"{k}: {v}" for k,v in headers.items()]
                    raw = "\n".join(lines) + "\n\n" + str(source.get("post_data") or "")
            except Exception as exc:
                self._append_terminal_line(f"[repeater] finding snapshot lookup failed: {exc}")
        if not raw:
            self._append_terminal_line("[repeater] finding has no captured request snapshot; refusing to create a reduced GET request")
            QMessageBox.warning(self, "Missing request snapshot", "This finding does not contain the original request snapshot, so it was not sent to Repeater.")
            return
        st=self._new_repeater_tab(raw=raw,title=f"Finding {data['index']}")
        st["url"]=url; st["target"].setText(f"Target: {self.target_url or url}")
        self.pages.setCurrentIndex(2); self.nav_repeater.setChecked(True); self._sync_repeater_views()
        self._append_terminal_line(f"[repeater] opened verified finding #{data['index']}; replaying exploit request")
        # Finding -> Repeater is an explicit user action. Replay the exact
        # exploit request immediately so the real target response is visible.
        self._repeater_send_request()

    def _send_finding_to_terminal(self, finding):
        """Legacy compatibility stub: Terminal was removed in v3.45."""
        if hasattr(self, "_append_exploit_output"):
            self._append_exploit_output("[scanner] Terminal action removed in v3.45.0")

    def _attach_code_highlighter(self, widget, mode="http"):
        hl=CtfSyntaxHighlighter(widget.document(), mode=mode)
        widget._ctf_highlighter=hl
        return hl

    def _pretty_body(self, body_text, content_type=""):
        """Best-effort formatting for JSON/HTML while leaving Raw untouched."""
        import json, re
        ctype=(content_type or "").lower()
        if "application/json" in ctype or body_text.lstrip().startswith(("{", "[")):
            try: return json.dumps(json.loads(body_text), indent=2, ensure_ascii=False)
            except Exception: pass
        if "text/html" in ctype or re.search(r"<\/?[A-Za-z][^>]*>", body_text):
            # Keep text readable without attempting a destructive HTML rewrite.
            pretty=re.sub(r">\s*<", ">\n<", body_text.strip())
            lines=[]; indent=0
            void={"area","base","br","col","embed","hr","img","input","link","meta","param","source","track","wbr"}
            for line in pretty.splitlines():
                t=line.strip()
                if not t: continue
                if re.match(r"</",t): indent=max(0,indent-1)
                lines.append("  "*indent+t)
                opens=len(re.findall(r"<([A-Za-z][^/!>\s]*)(?:\s[^>]*)?>",t))
                closes=len(re.findall(r"</[A-Za-z][^>]*>",t))
                tags=[x.lower() for x in re.findall(r"<([A-Za-z][^/!>\s]*)(?:\s[^>]*)?>",t)]
                for tag in tags:
                    if tag not in void and not re.search(r"</\s*"+re.escape(tag)+r"\s*>",t): indent += 1
                indent=max(0,indent-(max(0,closes-1)))
            return "\n".join(lines)
        return body_text

    def _build_repeater_page(self):
        page=QWidget(); page.setObjectName("repeater_page")
        root=QVBoxLayout(page); root.setContentsMargins(10,8,10,8); root.setSpacing(6)
        top=QHBoxLayout(); top.setSpacing(6)
        self.repeater_sessions=QTabWidget(); self.repeater_sessions.setObjectName("repeater_sessions"); self.repeater_sessions.setTabsClosable(True)
        self.repeater_sessions.currentChanged.connect(self._activate_repeater_instance)
        self.repeater_sessions.tabCloseRequested.connect(self._close_repeater_tab)
        plus=QPushButton("+"); plus.setObjectName("repeater_tool"); plus.clicked.connect(lambda: self._new_repeater_tab())
        top.addWidget(self.repeater_sessions,1); top.addWidget(plus); root.addLayout(top)
        self._repeater_instances=[]
        self._new_repeater_tab(title="Repeater 1")
        return page

    def _new_repeater_tab(self, raw=None, title=None):
        state_id=len(getattr(self,'_repeater_instances',[]))+1
        page=QWidget(); root=QVBoxLayout(page); root.setContentsMargins(4,4,4,4); root.setSpacing(6)
        toolbar=QHBoxLayout(); send=QPushButton("Send"); send.setObjectName("repeater_send"); clear=QPushButton("Clear"); clear.setObjectName("repeater_tool"); target=QLabel("Target: —"); target.setObjectName("repeater_target")
        toolbar.addWidget(send); toolbar.addWidget(QPushButton("⚙")); toolbar.addWidget(QPushButton("‹")); toolbar.addWidget(QPushButton("›")); toolbar.addStretch(1); toolbar.addWidget(target); toolbar.addWidget(clear); root.addLayout(toolbar)
        split=QSplitter(Qt.Orientation.Horizontal); split.setObjectName("repeater_splitter"); split.setChildrenCollapsible(False)
        left=QFrame(); left.setObjectName("repeater_root"); lv=QVBoxLayout(left); lv.setContentsMargins(0,0,0,0); lv.setSpacing(0)
        tabs=QTabWidget(); tabs.setObjectName("repeater_tabs")
        req=QPlainTextEdit(); req.setObjectName("http_editor"); self._install_text_context_menu(req); req.setPlainText(raw or "GET / HTTP/1.1\nHost: target.example\nConnection: close\n\n"); self._attach_code_highlighter(req,"request"); tabs.addTab(req,"Pretty")
        rawv=QPlainTextEdit(); rawv.setObjectName("http_editor"); self._install_text_context_menu(rawv); self._attach_code_highlighter(rawv,"http"); tabs.addTab(rawv,"Raw")
        hx=QPlainTextEdit(); hx.setObjectName("http_editor"); hx.setReadOnly(True); tabs.addTab(hx,"Hex")
        jwt=QWidget(); jlay=QHBoxLayout(jwt); jlay.setContentsMargins(8,8,8,8)
        col=QVBoxLayout(); col.addWidget(QLabel("JWT Header")); jh=QPlainTextEdit(); jh.setObjectName("jwt_editor"); self._attach_code_highlighter(jh,"json"); col.addWidget(jh,1); col.addWidget(QLabel("JWT Payload")); jp=QPlainTextEdit(); jp.setObjectName("jwt_editor"); self._attach_code_highlighter(jp,"json"); col.addWidget(jp,1); col.addWidget(QLabel("Signature")); js=QPlainTextEdit(); js.setObjectName("jwt_editor"); self._attach_code_highlighter(js,"http"); js.setMaximumHeight(100); col.addWidget(js); jlay.addLayout(col,2)
        opts=QGroupBox("JWT Signature"); ov=QVBoxLayout(opts); group=QButtonGroup(page)
        rb1=QRadioButton("Do not automatically modify signature"); rb2=QRadioButton("Recalculate Signature"); rb3=QRadioButton("Keep original signature"); rb4=QRadioButton("Sign with random key pair"); rb5=QRadioButton("Load Secret / Key from File"); rb1.setChecked(True)
        for rb in (rb1,rb2,rb3,rb4,rb5): group.addButton(rb); ov.addWidget(rb)
        ov.addWidget(QLabel("Secret / Key:")); secret=QPlainTextEdit(); secret.setMaximumHeight(70); ov.addWidget(secret)
        alg=QComboBox(); alg.addItems(["—","Set alg=none","Set alg=None","Set algorithm to NONE"]); ov.addWidget(QLabel("Algorithm mutation:")); ov.addWidget(alg)
        apply_jwt=QPushButton("Apply JWT to Request"); apply_jwt.setObjectName("repeater_tool"); ov.addWidget(apply_jwt)
        cve=QCheckBox("CVE-2018-0114 Attack"); cve.setEnabled(False); cve.setToolTip("Reserved for JWK-based manual analysis"); ov.addWidget(cve); ov.addStretch(1); jlay.addWidget(opts,1); tabs.addTab(jwt,"JSON Web Tokens")
        lv.addWidget(tabs,1); split.addWidget(left)
        respf=QFrame(); respf.setObjectName("repeater_response_panel"); rv=QVBoxLayout(respf); rv.setContentsMargins(0,0,0,0); rv.setSpacing(0); rt=QTabWidget(); rt.setObjectName("repeater_tabs")
        resp=QPlainTextEdit(); resp.setObjectName("http_editor"); resp.setReadOnly(True); self._attach_code_highlighter(resp,"response"); rt.addTab(resp,"Pretty")
        respr=QPlainTextEdit(); respr.setObjectName("http_editor"); respr.setReadOnly(True); self._attach_code_highlighter(respr,"http"); rt.addTab(respr,"Raw")
        resph=QPlainTextEdit(); resph.setObjectName("http_editor"); resph.setReadOnly(True); rt.addTab(resph,"Hex")
        resprender=QTextBrowser(); resprender.setObjectName("http_render"); resprender.setOpenExternalLinks(False); resprender.setOpenLinks(False); rt.addTab(resprender,"Render")
        rv.addWidget(rt,1); split.addWidget(respf)
        insp=QFrame(); il=QVBoxLayout(insp); il.addWidget(QLabel("Inspector"))
        for name in ("Request attributes","Request queue","Request body","Request cookies","Request headers","Response headers"): il.addWidget(QPushButton(name+"   ›"))
        il.addStretch(1); split.addWidget(insp); split.setSizes([650,650,220]); root.addWidget(split,1)
        state={"page":page,"tabs":tabs,"response_tabs":rt,"send":send,"clear":clear,"target":target,"req":req,"raw":rawv,"hex":hx,"jwt_header":jh,"jwt_payload":jp,"jwt_sig":js,"jwt_secret":secret,"jwt_algnone":alg,"jwt_cve":cve,"jwt_apply":apply_jwt,"jwt_sig_group":group,"jwt_recalc":rb2,"jwt_keep":rb3,"resp":resp,"resp_raw":respr,"resp_hex":resph,"resp_render":resprender,"url":"","running":False}
        self._repeater_instances.append(state); send.clicked.connect(self._repeater_send_request); clear.clicked.connect(self.repeater_request_clear); req.textChanged.connect(self._sync_repeater_views); apply_jwt.clicked.connect(self._apply_jwt_to_request)
        tab=self.repeater_sessions.addTab(page,title or f"Repeater {state_id}"); self.repeater_sessions.setCurrentIndex(tab); self._activate_repeater_instance(tab); return state

    def _activate_repeater_instance(self,index):
        if index<0 or index>=len(getattr(self,'_repeater_instances',[])): return
        active=getattr(self,'_active_repeater_index',0)
        if getattr(self,'_repeater_browser_active',False) and index!=active:
            try: self.repeater_sessions.blockSignals(True); self.repeater_sessions.setCurrentIndex(active)
            finally: self.repeater_sessions.blockSignals(False)
            return
        st=self._repeater_instances[index]
        self._active_repeater_index=index
        self.repeater_tabs=st["tabs"]; self.repeater_response_tabs=st["response_tabs"]; self.repeater_send=st["send"]; self.repeater_request=st["req"]; self.repeater_raw_alias=st["raw"]; self.repeater_hex=st["hex"]; self.jwt_header_editor=st["jwt_header"]; self.jwt_payload_editor=st["jwt_payload"]; self.jwt_signature_editor=st["jwt_sig"]; self.jwt_secret_input=st["jwt_secret"]; self.jwt_alg_none=st["jwt_algnone"]; self.jwt_cve=st["jwt_cve"]; self.jwt_apply=st["jwt_apply"]; self.jwt_recalc=st["jwt_recalc"]; self.jwt_keep=st["jwt_keep"]; self.repeater_response=st["resp"]; self.repeater_response_raw=st["resp_raw"]; self.repeater_response_hex=st["resp_hex"]; self.repeater_response_render=st["resp_render"]; self.repeater_target_label=st["target"]

    def _close_repeater_tab(self,index):
        if len(self._repeater_instances)<=1: self.repeater_request_clear(); return
        st=self._repeater_instances.pop(index); self.repeater_sessions.removeTab(index); st["page"].deleteLater()
        self._activate_repeater_instance(min(index,self.repeater_sessions.count()-1))

    def repeater_request_clear(self):
        self.repeater_request.clear(); self.repeater_raw_alias.clear(); self.jwt_header_editor.clear(); self.jwt_payload_editor.clear(); self.jwt_signature_editor.clear(); self.repeater_hex.clear(); self._sync_repeater_views()

    def _extract_jwt_from_text(self, text):
        import re, json, base64
        m = re.search(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", text)
        if not m: return None
        token = m.group(0)
        parts = token.split('.')
        try:
            dec=lambda x: json.loads(base64.urlsafe_b64decode(x + '='*((4-len(x)%4)%4)).decode())
            return token, dec(parts[0]), dec(parts[1]), parts[2]
        except Exception:
            return None

    def _sync_repeater_views(self):
        text=self.repeater_request.toPlainText(); self.repeater_raw_alias.setPlainText(text)
        self.repeater_hex.setPlainText(' '.join(f'{b:02x}' for b in text.encode('utf-8', errors='replace')))
        info=self._extract_jwt_from_text(text)
        if info:
            token, header, payload, sig=info
            self.jwt_header_editor.setPlainText(json.dumps(header, indent=2))
            self.jwt_payload_editor.setPlainText(json.dumps(payload, indent=2))
            self.jwt_signature_editor.setPlainText(sig)
            self.repeater_tabs.setTabText(3, "JSON Web Tokens")
        else:
            self.jwt_header_editor.setPlainText("No JWT detected in request")
            self.jwt_payload_editor.clear(); self.jwt_signature_editor.clear()
            self.repeater_tabs.setTabText(3, "JSON Web Tokens")

    def _apply_jwt_to_request(self):
        """Apply the edited JWT header/payload/signature back into the raw request.

        This is deliberately explicit: changing the editors never silently mutates
        the request. The user presses Apply JWT to Request, Burp-like behavior for
        manual JWT testing.
        """
        import base64, hashlib, hmac, json, re
        info = self._extract_jwt_from_text(self.repeater_request.toPlainText())
        if not info:
            self.repeater_response.setPlainText("[JWT] No JWT found in request")
            return
        old_token, old_header, old_payload, old_sig = info
        try:
            header = json.loads(self.jwt_header_editor.toPlainText())
            payload = json.loads(self.jwt_payload_editor.toPlainText())
        except Exception as exc:
            self.repeater_response.setPlainText(f"[JWT] Invalid JSON: {exc}")
            return
        def b64url(obj):
            raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        mode_text = self.jwt_alg_none.currentText().lower()
        force_none = "none" in mode_text
        if force_none:
            header["alg"] = "none"
            token = b64url(header) + "." + b64url(payload) + "."
        else:
            head = b64url(header)
            body = b64url(payload)
            signing = f"{head}.{body}".encode("ascii")
            if self.jwt_recalc.isChecked():
                secret = self.jwt_secret_input.toPlainText().strip()
                if not secret:
                    self.repeater_response.setPlainText("[JWT] Enter Secret / Key before recalculating HS256 signature")
                    return
                alg = str(header.get("alg", "HS256")).upper()
                if alg != "HS256":
                    self.repeater_response.setPlainText(f"[JWT] Recalculate currently supports HS256; current alg={alg}")
                    return
                sig = hmac.new(secret.encode("utf-8", "surrogatepass"), signing, hashlib.sha256).digest()
                token = f"{head}.{body}." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
            else:
                sig = self.jwt_signature_editor.toPlainText().strip() or old_sig
                token = f"{head}.{body}.{sig}"
        updated = self.repeater_request.toPlainText().replace(old_token, token, 1)
        self.repeater_request.setPlainText(updated)
        self._sync_repeater_views()
        self._append_terminal_line("[jwt] JWT mutation applied to Repeater request")

    def _repeater_send_request(self):
        raw = self.repeater_request.toPlainText().strip()
        if not raw:
            self.repeater_response.setPlainText("[!] Empty request")
            return
        try:
            parsed = self._parse_raw_http_request(raw)
        except ValueError as exc:
            self.repeater_response.setPlainText(f"[Repeater] Invalid request\n\n[!] {exc}")
            return
        if (self._repeater_worker is not None and self._repeater_worker.isRunning()) or self._repeater_browser_active:
            self.repeater_response.setPlainText("[Repeater] A request is already running.")
            return
        self.repeater_send.setEnabled(False)
        self.repeater_send.setText("SENDING...")
        self.repeater_response.setPlainText(
            f"[Repeater] Sending {parsed['method']} {parsed['url']}...\n"
        )
        self._append_terminal_line(f"[repeater] sending {parsed['method']} {parsed['url']}")

        # Preferred path: reuse the live browser context. This is the closest
        # local equivalent to Burp's project/session-aware Repeater.
        browser = self.browser_worker
        if browser is not None and browser.isRunning() and browser.loop is not None:
            if browser.send_repeater_request(
                parsed["method"], parsed["url"], parsed["headers"],
                parsed["body"].encode("utf-8", "surrogatepass"), getattr(self,"_active_repeater_index",0),
            ):
                self._repeater_browser_active = True
                self._repeater_worker = None
                return

        async def _send_fallback():
            import copy
            from core.models import SessionSnapshot
            from core.session import SessionHttpClient
            base_snapshot = copy.deepcopy(self.snapshot) if self.snapshot is not None else SessionSnapshot(current_url=parsed["url"])
            base_snapshot.current_url = parsed["url"]
            client = SessionHttpClient(base_snapshot, timeout=20.0, logger=self._append_terminal_line)
            try:
                response = await client.request(
                    parsed["method"], parsed["url"],
                    headers=parsed["headers"],
                    content=parsed["body"].encode("utf-8", "surrogatepass"),
                    timeout=20.0, follow_redirects=True,
                )
                return {
                    "status": response.status_code,
                    "status_text": response.reason_phrase,
                    "url": str(response.url),
                    "http_version": response.http_version or "HTTP/1.1",
                    "headers": dict(response.headers),
                    "body": response.content,
                }
            finally:
                await client.close()

        self._repeater_browser_active = False
        self._repeater_worker = AsyncWorker(_send_fallback)
        worker = self._repeater_worker
        worker.done.connect(self._repeater_request_done)
        worker.failed.connect(self._repeater_request_failed)
        worker.finished.connect(lambda w=worker: self._repeater_worker_finished(w))
        worker.start()

    def _parse_raw_http_request(self, raw):
        from urllib.parse import urlsplit, urlunsplit

        normalized = raw.replace("\r\n", "\n")
        head, sep, body = normalized.partition("\n\n")
        lines = head.split("\n")
        if not lines or len(lines[0].split()) < 2:
            raise ValueError("First line must look like: GET /path HTTP/1.1")

        parts = lines[0].split(None, 2)
        method = parts[0].upper()
        target = parts[1]
        headers = {}
        for line in lines[1:]:
            if not line.strip():
                continue
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()

        host = headers.get("Host") or headers.get("host")
        if not host and not self.target_url:
            raise ValueError("Host header is required")

        if target.startswith("http://") or target.startswith("https://"):
            url = target
        else:
            scheme = "https" if self.target_url.startswith("https://") else "http"
            if host:
                url = f"{scheme}://{host}{target if target.startswith('/') else '/' + target}"
            else:
                parsed_target = urlsplit(self.target_url)
                path = target if target.startswith("/") else "/" + target
                url = urlunsplit((parsed_target.scheme, parsed_target.netloc, path, "", ""))

        # Preserve duplicate/case-insensitive behavior as far as a normal HTTP
        # client allows; header names themselves are case-insensitive.
        return {"method": method, "url": url, "headers": headers, "body": body}

    def _format_repeater_response(self, response, body):
        http_version = str(response.http_version or "HTTP/1.1")
        if not http_version.upper().startswith("HTTP/"):
            http_version = "HTTP/" + http_version
        status_line = f"{http_version} {response.status_code} {response.reason_phrase}"
        header_lines = [f"{k}: {v}" for k, v in response.headers.multi_items()]
        header_block = "\n".join(header_lines)
        try:
            text = body.decode(response.encoding or "utf-8", errors="replace")
        except Exception:
            text = body.decode("utf-8", errors="replace")
        return (
            f"{status_line}\n{header_block}\n\n"
            f"{text}"
        )

    def _handle_repeater_result(self, result):
        if isinstance(result, dict):
            status = int(result.get("status", 0))
            reason = result.get("status_text", "") or ""
            body = result.get("body", b"") or b""
            http_version = result.get("http_version", "HTTP/1.1") or "HTTP/1.1"
            headers = result.get("headers", {}) or {}
        else:
            response, body = result
            status = response.status_code
            reason = response.reason_phrase
            http_version = response.http_version or "HTTP/1.1"
            headers = dict(response.headers)
        if not str(http_version).upper().startswith("HTTP/"):
            http_version = "HTTP/" + str(http_version)
        status_line = f"{http_version} {status} {reason}".rstrip()
        formatted = status_line + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n\n"
        try:
            formatted += body.decode("utf-8", errors="replace")
        except Exception:
            formatted += str(body)
        pretty_body=self._pretty_body(body.decode("utf-8", errors="replace"), headers.get("content-type", ""))
        pretty_formatted = status_line + "\n" + "\n".join(f"{k}: {v}" for k,v in headers.items()) + "\n\n" + pretty_body
        self.repeater_response.setPlainText(pretty_formatted)
        self.repeater_response_raw.setPlainText(formatted)
        self.repeater_response_hex.setPlainText(" ".join(f"{b:02x}" for b in body[:32768]))
        ctype = ""
        for k, v in headers.items():
            if str(k).lower() == "content-type":
                ctype = str(v)
                break
        body_text = body.decode("utf-8", errors="replace")
        if hasattr(self, "repeater_response_render"):
            if "text/html" in ctype.lower():
                self.repeater_response_render.setHtml(body_text)
            else:
                self.repeater_response_render.setPlainText(body_text or "(empty response)")
        self.repeater_send.setEnabled(True)
        self.repeater_send.setText("SEND REQUEST")
        self._append_terminal_line(f"[repeater] response {status} {reason} ({len(body)} bytes)")

    @Slot(object)
    def _repeater_request_done(self, result):
        self._handle_repeater_result(result)

    @Slot(object)
    def _repeater_browser_response(self, result):
        tab_index=result.get("tab_index") if isinstance(result,dict) else None
        payload=result.get("result") if isinstance(result,dict) and "result" in result else result
        old=getattr(self,"_active_repeater_index",0)
        if isinstance(tab_index,int) and 0<=tab_index<len(self._repeater_instances):
            self._activate_repeater_instance(tab_index)
        self._repeater_browser_active=False; self._handle_repeater_result(payload)
        if isinstance(tab_index,int) and 0<=old<len(self._repeater_instances): self._activate_repeater_instance(old)

    @Slot(str)
    def _repeater_browser_error(self, error):
        self._repeater_browser_active = False
        self._repeater_request_failed(error)

    def _repeater_worker_finished(self, worker):
        if self._repeater_worker is worker:
            self._repeater_worker = None
        worker.deleteLater()

    @Slot(str)
    def _repeater_request_failed(self, error):
        self._repeater_browser_active = False
        self.repeater_response.setPlainText(
            "[Repeater] Request failed\n\n[ERROR] " + error
        )
        self.repeater_send.setEnabled(True)
        self.repeater_send.setText("SEND REQUEST")
        self._append_terminal_line(f"[repeater] error: {error}")
        # Keep the QThread object referenced until its finished signal fires.

    def _build_intruder_page(self):
        page = QWidget()
        page.setObjectName("page")
        content = QVBoxLayout(page)
        content.setContentsMargins(34, 30, 34, 30)
        content.setSpacing(14)

        kicker = QLabel("CTF / WEB EXPLOITATION")
        kicker.setObjectName("page_kicker")
        title = QLabel("Intruder")
        title.setObjectName("page_title")
        content.addWidget(kicker)
        content.addWidget(title)

        toolbar = QHBoxLayout()
        self.intercept_toggle = QPushButton("◎  INTERCEPT OFF")
        self.intercept_toggle.setObjectName("intercept_toggle")
        self.intercept_toggle.setCheckable(True)
        self.intercept_toggle.setMinimumHeight(40)
        self.intercept_toggle.clicked.connect(self._toggle_intercept)
        self.intruder_forward = QPushButton("→  FORWARD")
        self.intruder_forward.setObjectName("intercept_forward")
        self.intruder_forward.setMinimumHeight(40)
        self.intruder_forward.clicked.connect(lambda: self._resolve_intercept("forward"))
        self.intruder_drop = QPushButton("DROP")
        self.intruder_drop.setObjectName("intercept_drop")
        self.intruder_drop.setMinimumHeight(40)
        self.intruder_drop.clicked.connect(lambda: self._resolve_intercept("drop"))
        self.intruder_forward.setEnabled(False)
        self.intruder_drop.setEnabled(False)
        toolbar.addWidget(self.intercept_toggle, 1)
        toolbar.addWidget(self.intruder_forward)
        toolbar.addWidget(self.intruder_drop)
        content.addLayout(toolbar)

        self.intercept_status = QLabel("Intercept OFF — browser traffic passes through normally.")
        self.intercept_status.setObjectName("exploit_status")
        content.addWidget(self.intercept_status)

        split = QSplitter(Qt.Orientation.Horizontal)
        queue_box = QGroupBox("Intercepted Requests")
        ql = QVBoxLayout(queue_box)
        self.intercept_table = QTableWidget(0, 4)
        self.intercept_table.setObjectName("intruder_table")
        self.intercept_table.setHorizontalHeaderLabels(["#", "Method", "URL", "Type"])
        self.intercept_table.verticalHeader().setVisible(False)
        self.intercept_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.intercept_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.intercept_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.intercept_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.intercept_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.intercept_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.intercept_table.itemSelectionChanged.connect(self._load_selected_intercept)
        ql.addWidget(self.intercept_table)

        editor_box = QGroupBox("Request")
        el = QVBoxLayout(editor_box)
        self.intruder_request = QPlainTextEdit()
        self._install_text_context_menu(self.intruder_request)
        self.intruder_request.setObjectName("http_editor")
        self.intruder_request.setPlaceholderText("Intercepted HTTP request will appear here...")
        el.addWidget(self.intruder_request, 1)
        edit_note = QLabel("Edit the request, then press FORWARD. DROP aborts the request.")
        edit_note.setObjectName("exploit_status")
        el.addWidget(edit_note)

        split.addWidget(queue_box)
        split.addWidget(editor_box)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 2)
        content.addWidget(split, 1)

        self._intercept_queue = []
        self._active_intercept = None
        self._intercept_by_token = {}
        return page

    def _toggle_intercept(self, checked):
        self.intercept_toggle.setText("◎  INTERCEPT ON" if checked else "◎  INTERCEPT OFF")
        if self.browser_worker and self.browser_worker.isRunning():
            self.browser_worker.set_intercept(checked)
            self.intercept_status.setText(
                "Intercept ON — browser requests pause here until FORWARD or DROP."
                if checked else
                "Intercept OFF — browser requests pass through normally."
            )
        else:
            self.intercept_status.setText(
                "Intercept ON — browser requests will pause here when Chromium starts."
                if checked else
                "Intercept OFF — browser requests pass through normally."
            )
        self._append_terminal_line(f"[intruder] intercept {'enabled' if checked else 'disabled'}")

    def _on_intercept_recorded(self, record):
        self._intercept_queue.append(record)
        self._intercept_by_token[record["token"]] = record
        row = self.intercept_table.rowCount()
        self.intercept_table.insertRow(row)
        values = [str(row + 1), record["method"], record["url"], record["resource_type"]]
        for col, value in enumerate(values):
            self.intercept_table.setItem(row, col, QTableWidgetItem(value))
        if self._active_intercept is None:
            self.intercept_table.selectRow(row)
        self.intercept_status.setText(f"{len(self._intercept_queue)} request(s) waiting for action")

    def _load_selected_intercept(self):
        row = self.intercept_table.currentRow()
        if row < 0 or row >= len(self._intercept_queue):
            self._active_intercept = None
            self.intruder_forward.setEnabled(False)
            self.intruder_drop.setEnabled(False)
            return
        record = self._intercept_queue[row]
        self._active_intercept = record
        lines = [f"{record['method']} {record['url']} HTTP/1.1"]
        headers = record.get("headers") or {}
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if record.get("post_data"):
            lines.append(record["post_data"])
        self.intruder_request.setPlainText("\n".join(lines))
        self.intruder_forward.setEnabled(True)
        self.intruder_drop.setEnabled(True)

    def _resolve_intercept(self, action):
        record = self._active_intercept
        if not record or not self.browser_worker:
            return
        edited = None
        if action == "forward":
            raw = self.intruder_request.toPlainText()
            edited = self._parse_request_editor(raw, record)
        ok = self.browser_worker.resolve_intercept(record["token"], action, edited)
        if ok:
            row = self.intercept_table.currentRow()
            if row >= 0:
                self.intercept_table.removeRow(row)
                self._intercept_queue = [r for r in self._intercept_queue if r["token"] != record["token"]]
            self._active_intercept = None
            self.intruder_request.clear()
            self.intruder_forward.setEnabled(False)
            self.intruder_drop.setEnabled(False)
            if self.intercept_table.rowCount() > 0:
                self.intercept_table.selectRow(0)
            self.intercept_status.setText(f"Request {action}ed. {len(self._intercept_queue)} request(s) waiting.")
            self._append_terminal_line(f"[intruder] request {action}ed: {record['method']} {record['url']}")

    def _parse_request_editor(self, raw, original):
        lines = raw.splitlines()
        if not lines:
            return None
        method = original["method"]
        url = original["url"]
        if lines[0].strip():
            first = lines[0].split()
            if len(first) >= 2:
                method, url = first[0], first[1]
        headers = {}
        body_lines = []
        in_body = False
        for line in lines[1:]:
            if not in_body and not line.strip():
                in_body = True
                continue
            if not in_body and ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
            elif in_body:
                body_lines.append(line)
        body = "\n".join(body_lines) if body_lines else None
        parsed = {"method": method, "url": url, "headers": headers}
        if body is not None:
            parsed["post_data"] = body
        return parsed

    def _launch_exploitation_ui(self):
        return self.start_exploitation()

    def _set_exploitation_running(self, running: bool):
        self._exploit_busy = bool(running)
        btn = getattr(self, "scan_start_button", None)
        if btn is not None:
            btn.setEnabled(not running)
        spinner = getattr(self, "_exploit_spinner", None)
        if running:
            self._exploit_spinner_index = 0
            if spinner is not None and not spinner.isActive():
                spinner.start()
        elif spinner is not None and spinner.isActive():
            spinner.stop()

    def _update_exploit_spinner(self):
        if not self._exploit_busy:
            return
        dots = "." * (self._exploit_spinner_index % 4)
        self._exploit_spinner_index += 1
        self.scan_status_label.setText(f"RUNNING{dots}")

    def _append_exploit_output(self, text: str):
        if hasattr(self, "exploit_output") and text:
            self.exploit_output.appendPlainText(text)

    def _toggle_sidebar(self):
        self.sidebar_collapsed = not self.sidebar_collapsed
        if self.sidebar_collapsed:
            self.sidebar.setFixedWidth(72)
            self.brand.setText("K_C0NK")
            self.brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.brand.setFont(QFont("Sans Serif", 14, QFont.Weight.Bold))
            self.subtitle.hide()
            self.nav_dashboard.setText("⌂")
            self.nav_exploitation.setText("⚡")
            self.nav_repeater.setText("↻")
            for btn in (self.nav_dashboard, self.nav_exploitation, self.nav_repeater):
                if btn is self.nav_dashboard: tip = "Dashboard"
                elif btn is self.nav_exploitation: tip = "Scanner"
                else: tip = "Repeater"
                btn.setToolTip(tip)
                btn.setMinimumWidth(40)
        else:
            self.sidebar.setFixedWidth(220)
            self.brand.setText("K_C0NK")
            self.brand.setAlignment(Qt.AlignmentFlag.AlignLeft)
            self.brand.setFont(QFont("Sans Serif", 17, QFont.Weight.Bold))
            self.subtitle.show()
            self.nav_dashboard.setText("⌂   Dashboard")
            self.nav_exploitation.setText("⚡  Scanner")
            self.nav_repeater.setText("↻  Repeater")
            for btn in (self.nav_dashboard, self.nav_exploitation, self.nav_repeater):
                btn.setMinimumWidth(0)

    def _switch_page(self, index: int):
        self.pages.setCurrentIndex(index)

    def log(self, text: str):
        if hasattr(self, "output") and self.output is not None:
            self.output.appendPlainText(text)
        if hasattr(self, "exploit_output") and self.pages.currentIndex() == 1:
            self.exploit_output.appendPlainText(text)
        if hasattr(self, "terminal_view"):
            self.terminal_view.appendPlainText(text)

    def _terminal_command(self):
        command = self.terminal_input.text().strip()
        if not command:
            return
        if not self.execution_ready:
            self.terminal_view.appendPlainText("[locked] Command execution is disabled until an execution-capable finding is detected (e.g. SSTI/RCE/upload).")
            self.terminal_input.clear()
            return
        self.terminal_view.appendPlainText(f"ctf@workbench:~$ {command}")
        if command in {"clear", "cls"}:
            self.terminal_view.clear()
        elif command == "help":
            self.terminal_view.appendPlainText("Available: help, clear, status")
        elif command == "status":
            running = bool(self.browser_worker and self.browser_worker.isRunning())
            self.terminal_view.appendPlainText(f"Browser: {'connected' if running else 'disconnected'}")
        else:
            self.terminal_view.appendPlainText(f"Command not handled by UI shell: {command}")
        self.terminal_input.clear()

    def _update_execution_gate(self, capabilities=None):
        caps = [str(x) for x in (capabilities or []) if x]
        for cap in caps:
            if cap not in self.execution_capabilities:
                self.execution_capabilities.append(cap)
        self.execution_ready = bool(self.execution_capabilities)
        if hasattr(self, "terminal_run_button"):
            self.terminal_run_button.setEnabled(self.execution_ready)
            if self.execution_ready:
                reason = ", ".join(self.execution_capabilities[:4])
                self.terminal_run_button.setToolTip(f"Execution path detected: {reason}")
                if hasattr(self, "terminal_gate_status"):
                    self.terminal_gate_status.setText(f"Execution unlocked — detected: {reason}")
            else:
                self.terminal_run_button.setToolTip("Disabled until the exploitation workflow discovers an execution-capable path (e.g. SSTI/RCE/upload).")
                if hasattr(self, "terminal_gate_status"):
                    self.terminal_gate_status.setText("Execution locked — waiting for a confirmed/potential execution path.")

    def _reset_execution_gate(self):
        self.execution_ready = False
        self.execution_capabilities = []
        if hasattr(self, "terminal_run_button"):
            self.terminal_run_button.setEnabled(False)
            self.terminal_run_button.setToolTip("Disabled until the exploitation workflow discovers an execution-capable path (e.g. SSTI/RCE/upload).")
        if hasattr(self, "terminal_gate_status"):
            self.terminal_gate_status.setText("Execution locked — waiting for a confirmed/potential execution path.")

    def _validate(self):
        target = self.dashboard_url.text().strip() if hasattr(self, "dashboard_url") else ""
        ok, reason = validate_target(target)
        if not ok:
            QMessageBox.warning(self, "Target blocked", reason)
            return False
        if not target:
            QMessageBox.warning(self, "Target missing", "Submit a target URL from Dashboard first.")
            return False
        return True

    def _start_browser_for_target(self, target):
        # Each target gets a fresh browser worker/session so cookies, local storage,
        # history, and TLS/session state from a previous host cannot leak into it.
        self.target_url = target
        self._response_cache = []
        try:
            self.request_table.setRowCount(0)
        except Exception:
            pass
        self.log(f"[>] Opening {target}")
        self.browser_worker = BrowserWorker(target)
        self.browser_worker.browser_ready.connect(self._browser_ready)
        self.browser_worker.navigated.connect(self._browser_navigated)
        self.browser_worker.network_event.connect(self.log)
        self.browser_worker.request_recorded.connect(self._record_request_row)
        self.browser_worker.intercept_recorded.connect(self._on_intercept_recorded)
        self.browser_worker.set_intercept(self.intercept_toggle.isChecked())
        self.browser_worker.response_recorded.connect(self._record_response_row)
        self.browser_worker.repeater_response.connect(self._repeater_browser_response)
        self.browser_worker.repeater_error.connect(self._repeater_browser_error)
        self.browser_worker.error.connect(self._failed)
        self.browser_worker.finished.connect(self._browser_worker_finished)
        self.browser_worker.start()
        self.log("[+] Chromium worker started")

    def open_browser(self):
        if not self._validate():
            return
        target = self.dashboard_url.text().strip()
        if self.browser_worker and self.browser_worker.isRunning():
            current = self.target_url or getattr(self.browser_worker, "target_url", "")
            if current.rstrip('/') == target.rstrip('/'):
                self.log("[!] Browser is already running for this target")
                return
            # Switching targets must create a clean session. Request a graceful
            # shutdown, then start a brand-new browser worker after finished.
            self._pending_browser_target = target
            self.log(f"[>] Switching target: {current} -> {target}")
            self.browser_worker.close_browser()
            return
        self._start_browser_for_target(target)

    def _browser_worker_finished(self):
        worker = self.sender()
        if worker is self.browser_worker:
            self.browser_worker = None
        pending = self._pending_browser_target
        self._pending_browser_target = ""
        if pending and not self._closing:
            if self.dashboard_url.text().strip().rstrip('/') == pending.rstrip('/'):
                self._start_browser_for_target(pending)

    def _url_parts(self, url):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path.split("/")[0]
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        params = "&".join(parse_qs(parsed.query).keys()) if parsed.query else ""
        tls = "✓" if parsed.scheme == "https" else ""
        ip = ""
        try:
            import socket
            ip = socket.gethostbyname(parsed.hostname) if parsed.hostname else ""
        except Exception:
            pass
        return host, path, params, tls, ip

    def _record_request_row(self, request):
        url = request.get("url", "")
        host, path, params, tls, ip = self._url_parts(url)
        row = self.request_table.rowCount()
        self.request_table.insertRow(row)
        cookies = request.get("cookies", "") or request.get("headers", {}).get("cookie", "")
        values = [
            str(row + 1), host, request.get("method", "GET"), path, params, cookies, "", "", "",
            request.get("resource_type", "").upper(), "", "", "", tls, ip
        ]
        for col, value in enumerate(values):
            cell = QTableWidgetItem(value)
            if col == 0:
                cell.setData(Qt.ItemDataRole.UserRole, dict(request))
            self.request_table.setItem(row, col, cell)
        self.request_table.scrollToBottom()

    def _record_response_row(self, response):
        if not hasattr(self,"_response_cache"): self._response_cache=[]
        self._response_cache.append(response)
        self._response_cache=self._response_cache[-500:]
        url = response.get("url", "")
        status = str(response.get("status", ""))
        # Update the newest matching request instead of creating a duplicate row.
        for row in range(self.request_table.rowCount() - 1, -1, -1):
            path_item = self.request_table.item(row, 3)
            host_item = self.request_table.item(row, 1)
            if not path_item or not host_item:
                continue
            host, path, _, _, _ = self._url_parts(url)
            if host_item.text() == host and path_item.text() == path:
                # Table layout: #, Host, Method, URL, Params, Cookies, Edited,
                # Status code, Length, MIME type, Extension, Title, Notes, TLS, IP
                self.request_table.setItem(row, 7, QTableWidgetItem(status))
                self.request_table.setItem(row, 8, QTableWidgetItem(str(response.get("content_length", ""))))
                mime = response.get("content_type", "").split(";", 1)[0].strip()
                self.request_table.setItem(row, 9, QTableWidgetItem(mime))
                extension = ""
                cpath = path.split("?", 1)[0]
                if "." in cpath.rsplit("/", 1)[-1]:
                    extension = cpath.rsplit("/", 1)[-1].rsplit(".", 1)[-1].lower()
                self.request_table.setItem(row, 10, QTableWidgetItem(extension))
                if response.get("title"):
                    self.request_table.setItem(row, 11, QTableWidgetItem(response["title"]))
                return

    def _browser_ready(self, page_url):
        if self.request_table.rowCount() == 0:
            self._record_request_row({"method": "GET", "url": page_url, "resource_type": "document"})
        self.log(f"[browser] {page_url}")

    def _browser_navigated(self, page_url):
        self.log(f"[nav] {page_url}")

    def _capture_done(self, snapshot):
        self.snapshot = snapshot
        self.log(f"[live] Browser context updated from {snapshot.current_url}")
        self.log(f"[+] Visited pages: {len(snapshot.navigation_history)} | Requests: {len(snapshot.network_requests)}")

    def start_exploitation(self):
        if self.worker is not None and self.worker.isRunning():
            self.log("[!] Scanner is already running")
            return
        if not self._validate(): return
        if not self.browser_worker:
            QMessageBox.information(self, "Browser required", "Open Chromium first. The workbench follows the browser session and navigation.")
            return
        try:
            self.snapshot = self.browser_worker.capture()
            self._capture_done(self.snapshot)
        except Exception as exc:
            self._failed(str(exc))
            return
        selected = list(ALL_MODULES)
        self._exploit_target = self.dashboard_url.text().strip()
        self._reset_execution_gate()
        self.findings_table.setRowCount(0)
        self.scan_target_label.setText(f"Target: {self.target_url}")
        self.scan_status_label.setText("RUNNING")
        self.log("[+] Starting CTF exploitation engine")
        self.worker = AsyncWorker(lambda: self._exploit_async(selected))
        self.worker.log_message.connect(self._on_exploit_log)
        self.worker.done.connect(self._exploit_done)
        self.worker.failed.connect(self._failed)
        self.worker.finished.connect(self._exploit_worker_finished)
        self.worker.start()

    async def _exploit_async(self, selected):
        # IMPORTANT: never mutate Qt widgets from the worker thread.
        # The worker emits log_message; the GUI thread receives it via Qt signal.
        target = self._exploit_target
        engine = ExploitEngine(Target(target), self.snapshot, self.worker.log_message.emit, selected)
        return await engine.run()

    def _on_exploit_log(self, text: str):
        # One live log stream. ``log()`` already mirrors the exploitation
        # stream when the Exploitation page is active, so append here only
        # when that page is not active to avoid duplicate lines.
        self.log(text)
        if getattr(self.pages, "currentIndex", lambda: -1)() != 2:
            self._append_exploit_output(text)
        lower = text.lower()
        capability_hits = []
        if "potential expression evaluation" in lower or "ssti" in lower and "signal" in lower:
            capability_hits.append("SSTI / expression evaluation")
        if "rce" in lower or "remote code execution" in lower:
            capability_hits.append("RCE")
        if "upload" in lower and any(token in lower for token in ("endpoint", "file", "form", "found", "possible")):
            capability_hits.append("file upload path")
        if capability_hits:
            self._update_execution_gate(capability_hits)
        # Findings are promoted only from the engine's structured
        # ``findings.detected`` artifact in _exploit_done(). Plain log lines
        # such as HTTP 200/[signal] never create a fake finding.
        if text.startswith("[>] "):
            module_name = text[4:].strip()
            self.scan_terminal_hint.setText(f"Running module: {module_name}")

    def _exploit_done(self, result):
        results, artifacts = result
        found = []
        capability_hits = []
        if artifacts.get("execution.ssti"):
            capability_hits.append("SSTI / expression evaluation")
        if artifacts.get("execution.rce"):
            capability_hits.append("RCE")
        if artifacts.get("recon.upload_endpoints"):
            capability_hits.append("file upload path")
        if capability_hits:
            self._update_execution_gate(capability_hits)
        self._set_exploitation_running(False)
        timeout_count = sum(1 for item in results if getattr(item, "status", "") == "timeout")
        self.scan_status_label.setText("DONE" if not timeout_count else f"DONE ({timeout_count} TIMEOUT)")
        self.scan_terminal_hint.setText(
            f"Scan completed — {len(results)} module(s) executed; exploit verification completed."
        )
        self._append_exploit_output("")
        self._append_exploit_output("[+] Vulnerability scan complete")
        payloads = artifacts.get("payloads.summary", {}) if isinstance(artifacts, dict) else {}
        if payloads:
            total = sum(int(v) for v in payloads.values())
            self._append_exploit_output(f"[+] Payload inventory: {total} configured payload(s)")
            self._append_exploit_output("    " + " | ".join(f"{k}: {v}" for k, v in payloads.items()))
        coverage = artifacts.get("scanner.payload_coverage", {}) if isinstance(artifacts, dict) else {}
        if coverage:
            executed = sum(1 for bucket in coverage.values() if isinstance(bucket, list) for row in bucket if isinstance(row, dict) and row.get("executed"))
            verified = sum(1 for bucket in coverage.values() if isinstance(bucket, list) for row in bucket if isinstance(row, dict) and row.get("status") == "finding")
            not_observed = sum(1 for bucket in coverage.values() if isinstance(bucket, list) for row in bucket if isinstance(row, dict) and row.get("status") == "not-observed")
            self._append_exploit_output(f"[+] Payload execution ledger: executed={executed} | verified={verified} | not-observed={not_observed}")
        for item in results:
            status = getattr(item, "status", "")
            module = getattr(item, "module", "")
            message = getattr(item, "message", "")
            self._append_exploit_output(f"[{status}] {module}: {message}")
            evidence = getattr(item, "evidence", "") or ""
            for ev in evidence.splitlines()[:4]:
                self._append_exploit_output(f"    {ev}")
        findings = artifacts.get("findings.detected", []) if isinstance(artifacts, dict) else []
        for finding in findings:
            if isinstance(finding, dict):
                self._add_finding(
                    finding.get("url", ""),
                    finding.get("payload", ""),
                    finding.get("vulnerability", ""),
                    finding.get("response", ""),
                    finding.get("request_raw", ""),
                    finding_meta=finding,
                )
        self._append_terminal_line(f"[+] Findings displayed: {self.findings_table.rowCount()}")
        self._append_terminal_line("[+] Vulnerability scan complete")

    @Slot()
    def _exploit_worker_finished(self):
        worker = self.worker
        if worker is not None and not worker.isRunning():
            self.worker = None
            worker.deleteLater()

    def _failed(self, error):
        self._set_exploitation_running(False)
        self.scan_status_label.setText("ERROR")
        self.scan_terminal_hint.setText("Scan failed")
        self._append_exploit_output(f"[ERROR] {error}")
        self.log(f"[ERROR] {error}")
        if not getattr(self, "_shutdown_requested", False):
            QMessageBox.critical(self, "Error", error)

    def closeEvent(self, event):
        """Immediate hard shutdown requested by the user.

        No graceful worker wait, timer polling, or QThread cleanup is performed.
        This intentionally terminates the desktop process immediately.
        """
        try:
            event.accept()
        finally:
            import os
            os._exit(0)

