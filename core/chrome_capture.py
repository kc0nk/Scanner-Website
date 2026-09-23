from __future__ import annotations

import base64
import itertools
import json
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from urllib.request import urlopen

import websocket
from PySide6.QtCore import QThread, Signal


@dataclass
class CapturedTransaction:
    request_id: str
    tab_id: str
    resource_type: str = "Other"
    method: str = "GET"
    url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    status: int = 0
    status_text: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    mime_type: str = ""
    response_body: str = ""
    response_size: int = 0
    timestamp: float = 0.0
    duration_ms: int = 0
    wall_time: float = 0.0
    failed: str = ""


class ChromeCaptureThread(QThread):
    """Capture Chrome network activity through the Chrome DevTools Protocol (CDP)."""

    transaction = Signal(object)
    updated = Signal(object)
    error = Signal(str)
    state = Signal(str)

    def __init__(self, chrome_port: int, initial_url: str = "", parent=None):
        super().__init__(parent)
        self.chrome_port = chrome_port
        self.initial_url = initial_url
        self._stop = threading.Event()
        self._initial_navigation_started = threading.Event()
        self._tab_threads: dict[str, threading.Thread] = {}

    def stop(self):
        self._stop.set()

    def _json_get(self, path: str):
        with urlopen(f"http://127.0.0.1:{self.chrome_port}{path}", timeout=2) as r:
            return json.loads(r.read().decode("utf-8"))

    def _emit_body(self, record: CapturedTransaction, body: str):
        record.response_body = body
        self.updated.emit(record)

    def _attach_tab(self, target_id: str, ws_url: str, navigate_initial: bool = False):
        records: dict[str, CapturedTransaction] = {}
        pending_body: dict[int, str] = {}
        extra_request_headers: dict[str, dict[str, str]] = {}
        extra_response_headers: dict[str, dict[str, str]] = {}
        counter = itertools.count(100)
        ws = None
        try:
            ws = websocket.create_connection(
                ws_url,
                timeout=1.0,
                origin=f"http://127.0.0.1:{self.chrome_port}",
            )
            ws.settimeout(0.35)
            ws.send(json.dumps({"id": 1, "method": "Network.enable", "params": {
                "maxTotalBufferSize": 50 * 1024 * 1024,
                "maxResourceBufferSize": 10 * 1024 * 1024,
            }}))
            ws.send(json.dumps({"id": 2, "method": "Network.setCacheDisabled", "params": {"cacheDisabled": True}}))
            ws.send(json.dumps({"id": 3, "method": "Network.setBypassServiceWorker", "params": {"bypass": True}}))
            ws.send(json.dumps({"id": 4, "method": "Page.enable"}))
            # Only the first attached page is navigated to the requested target.
            # Additional tabs opened by the user must remain under their own URL.
            if navigate_initial and self.initial_url:
                ws.send(json.dumps({
                    "id": 5,
                    "method": "Page.navigate",
                    "params": {"url": self.initial_url},
                }))
            self.state.emit("Chrome network capture active")

            while not self._stop.is_set():
                try:
                    raw = ws.recv()
                    if not raw:
                        break
                    msg = json.loads(raw)
                except websocket.WebSocketTimeoutException:
                    continue
                except Exception:
                    break

                # Response to Network.getResponseBody.
                msg_id = msg.get("id")
                if msg_id in pending_body:
                    request_id = pending_body.pop(msg_id)
                    record = records.get(request_id)
                    if record:
                        result = msg.get("result") or {}
                        body = result.get("body")
                        if body is not None:
                            if result.get("base64Encoded"):
                                try:
                                    body = base64.b64decode(body).decode("utf-8", errors="replace")
                                except Exception:
                                    pass
                            record.response_body = body
                            self.updated.emit(record)
                    continue

                method = msg.get("method", "")
                p = msg.get("params") or {}
                request_id = p.get("requestId", "")

                if method == "Network.requestWillBeSent":
                    req = p.get("request") or {}
                    record = CapturedTransaction(
                        request_id=request_id,
                        tab_id=target_id,
                        resource_type=p.get("type", "Other") or "Other",
                        method=req.get("method", "GET") or "GET",
                        url=req.get("url", "") or "",
                        request_headers={str(k): str(v) for k, v in (req.get("headers") or {}).items()},
                        request_body=req.get("postData", "") or "",
                        timestamp=float(p.get("timestamp", 0.0) or 0.0),
                        wall_time=float(p.get("wallTime", 0.0) or 0.0),
                    )
                    merged_extra = extra_request_headers.pop(request_id, {})
                    if merged_extra:
                        record.request_headers.update(merged_extra)
                    records[request_id] = record
                    self.transaction.emit(record)

                elif method == "Network.requestWillBeSentExtraInfo":
                    headers = p.get("headers") or {}
                    normalized = {str(k): str(v) for k, v in headers.items()}
                    record = records.get(request_id)
                    if record:
                        record.request_headers.update(normalized)
                        self.updated.emit(record)
                    else:
                        extra_request_headers[request_id] = normalized

                elif method == "Network.responseReceived":
                    record = records.get(request_id)
                    if not record:
                        continue
                    resp = p.get("response") or {}
                    record.status = int(resp.get("status", 0) or 0)
                    record.status_text = resp.get("statusText", "") or ""
                    record.response_headers = {str(k): str(v) for k, v in (resp.get("headers") or {}).items()}
                    merged_extra = extra_response_headers.pop(request_id, {})
                    if merged_extra:
                        record.response_headers.update(merged_extra)
                    record.mime_type = resp.get("mimeType", "") or ""
                    self.updated.emit(record)

                elif method == "Network.responseReceivedExtraInfo":
                    headers = p.get("headers") or {}
                    normalized = {str(k): str(v) for k, v in headers.items()}
                    record = records.get(request_id)
                    if record:
                        record.response_headers.update(normalized)
                        self.updated.emit(record)
                    else:
                        extra_response_headers[request_id] = normalized

                elif method == "Network.loadingFinished":
                    record = records.get(request_id)
                    if not record:
                        continue
                    record.response_size = int(float(p.get("encodedDataLength", 0) or 0))
                    end = float(p.get("timestamp", record.timestamp) or record.timestamp)
                    record.duration_ms = max(0, int((end - record.timestamp) * 1000))
                    # Ask CDP for the response body. The result is handled by the same
                    # socket loop above, avoiding a nested recv/locking deadlock.
                    if record.resource_type not in {"WebSocket", "WebTransport"}:
                        cmd_id = next(counter)
                        pending_body[cmd_id] = request_id
                        ws.send(json.dumps({
                            "id": cmd_id,
                            "method": "Network.getResponseBody",
                            "params": {"requestId": request_id},
                        }))
                    self.updated.emit(record)

                elif method == "Network.loadingFailed":
                    record = records.get(request_id)
                    if not record:
                        continue
                    record.failed = p.get("errorText", "Request failed") or "Request failed"
                    self.updated.emit(record)
        finally:
            try:
                if ws:
                    ws.close()
            except Exception:
                pass

    def _discover_loop(self):
        while not self._stop.is_set():
            try:
                tabs = self._json_get("/json/list")
                for tab in tabs:
                    if tab.get("type") != "page":
                        continue
                    target_id = tab.get("id") or ""
                    ws_url = tab.get("webSocketDebuggerUrl") or ""
                    if not target_id or not ws_url or target_id in self._tab_threads:
                        continue
                    # Navigate only the first page that we attach to. New tabs/windows
                    # are captured as-is and are never redirected to the original URL.
                    navigate_initial = bool(self.initial_url and not self._initial_navigation_started.is_set())
                    if navigate_initial:
                        self._initial_navigation_started.set()
                    thread = threading.Thread(
                        target=self._attach_tab,
                        args=(target_id, ws_url, navigate_initial),
                        daemon=True,
                    )
                    self._tab_threads[target_id] = thread
                    thread.start()
            except Exception:
                pass
            time.sleep(0.5)

    def run(self):
        try:
            self.state.emit("Waiting for Chrome DevTools…")
            deadline = time.time() + 15
            ready = False
            while time.time() < deadline and not self._stop.is_set():
                try:
                    tabs = self._json_get("/json/list")
                    if any(t.get("type") == "page" and t.get("webSocketDebuggerUrl") for t in tabs):
                        ready = True
                        break
                except Exception:
                    pass
                time.sleep(0.25)
            if not ready:
                if not self._stop.is_set():
                    self.error.emit("Chrome DevTools endpoint did not become ready")
                return
            self._discover_loop()
        except Exception as exc:
            if not self._stop.is_set():
                self.error.emit(str(exc))


def find_free_port(start: int = 9222) -> int:
    for port in range(start, start + 100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise OSError("No free Chrome DevTools port available")


def find_chrome() -> str | None:
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        path = shutil.which(name)
        if path:
            return path
    return None


def launch_chrome(url: str, port: int | None = None):
    chrome = find_chrome()
    if not chrome:
        raise FileNotFoundError("Google Chrome/Chromium was not found in PATH")
    port = port or find_free_port()
    profile = tempfile.mkdtemp(prefix="ctf-exploit-workbench-chrome-")
    args = [
        chrome,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
        "--disable-features=Translate",
        "--remote-allow-origins=*",
        # Start blank. The capture thread attaches first, enables Network,
        # and then performs the real navigation so the initial request is captured.
        "about:blank",
    ]
    proc = subprocess.Popen(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return proc, port, profile
