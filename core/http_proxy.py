from __future__ import annotations

import select
import socket
import socketserver
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler

import httpx
from PySide6.QtCore import QThread, Signal

from core.http_tools import request_to_raw, response_to_raw


@dataclass
class ProxyMessage:
    message_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    client: str = ""
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    state: str = "QUEUED"
    response_raw: str = ""
    status: int = 0
    response_size: int = 0
    duration_ms: int = 0
    created_at: float = field(default_factory=time.time)


class _ProxyState:
    def __init__(self):
        self.lock = threading.RLock()
        self.pending: dict[str, tuple[ProxyMessage, threading.Event]] = {}
        self.intercept = False

    def enqueue(self, message: ProxyMessage) -> None:
        event = threading.Event()
        with self.lock:
            self.pending[message.message_id] = (message, event)
        event.wait(timeout=300)
        with self.lock:
            self.pending.pop(message.message_id, None)

    def action(self, message_id: str, state: str):
        with self.lock:
            pair = self.pending.get(message_id)
            if not pair:
                return
            pair[0].state = state
            pair[1].set()


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _Handler(BaseHTTPRequestHandler):
    server: _ThreadingHTTPServer

    def log_message(self, format, *args):
        return

    def _proxy(self):
        app: "LocalHttpProxy" = self.server.proxy_app
        length = int(self.headers.get("Content-Length", "0") or 0)
        body_bytes = self.rfile.read(length) if length else b""
        body = body_bytes.decode("utf-8", errors="replace")
        url = self.path
        if not url.startswith("http://") and not url.startswith("https://"):
            host = self.headers.get("Host", "")
            url = f"http://{host}{url}"
        headers = {k: v for k, v in self.headers.items() if k.lower() not in {"proxy-connection", "connection", "content-length"}}
        msg = ProxyMessage(client=str(self.client_address), method=self.command, url=url, headers=headers, body=body)
        app.message.emit(msg)
        if app._state.intercept:
            app._state.enqueue(msg)
            if msg.state == "DROPPED":
                self.send_error(502, "KCONK intercept dropped request")
                return
        started = time.perf_counter()
        try:
            with httpx.Client(timeout=20, follow_redirects=False, verify=False, http2=False) as client:
                response = client.request(self.command, url, headers=headers, content=body_bytes or None)
            elapsed = int((time.perf_counter() - started) * 1000)
            content = response.content
            msg.status = response.status_code
            msg.response_size = len(content)
            msg.duration_ms = elapsed
            response_body = content.decode("utf-8", errors="replace")
            msg.response_raw = response_to_raw(response.http_version, response.status_code, response.reason_phrase, dict(response.headers), response_body)
            msg.state = "FORWARDED"
            app.response.emit(msg)
            self.send_response(response.status_code, response.reason_phrase)
            hop = {"content-length", "transfer-encoding", "connection"}
            for key, value in response.headers.items():
                if key.lower() in hop:
                    continue
                try:
                    self.send_header(key, value)
                except UnicodeEncodeError:
                    continue
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as exc:
            msg.state = "ERROR"
            app.error.emit(f"Proxy request failed: {exc}")
            self.send_error(502, str(exc))

    def do_CONNECT(self):
        # HTTPS remains encrypted at the proxy layer. Browser/CDP capture is used
        # for decrypted HTTPS inspection; CONNECT is tunnelled transparently here.
        host, _, port = self.path.partition(":")
        upstream = None
        try:
            upstream = socket.create_connection((host, int(port or 443)), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()
            self.connection.settimeout(2.0)
            upstream.settimeout(2.0)
            sockets = [self.connection, upstream]
            while True:
                readable, _, _ = select.select(sockets, [], [], 2.0)
                if not readable:
                    continue
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    other = upstream if sock is self.connection else self.connection
                    other.sendall(data)
        except Exception:
            return
        finally:
            try:
                if upstream:
                    upstream.close()
            except Exception:
                pass

    def do_GET(self): self._proxy()
    def do_POST(self): self._proxy()
    def do_PUT(self): self._proxy()
    def do_PATCH(self): self._proxy()
    def do_DELETE(self): self._proxy()
    def do_OPTIONS(self): self._proxy()
    def do_HEAD(self): self._proxy()


class LocalHttpProxy(QThread):
    """Small local HTTP proxy for authorized testing.

    HTTP requests can be intercepted and released/dropped. HTTPS CONNECT is
    transparently tunnelled; browser/CDP capture remains responsible for
    decrypted HTTPS inspection.
    """

    message = Signal(object)
    response = Signal(object)
    error = Signal(str)
    state = Signal(str)

    def __init__(self, host: str = "127.0.0.1", port: int = 8080, parent=None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.server = None
        self._state = _ProxyState()

    @property
    def intercept(self) -> bool:
        return self._state.intercept

    def set_intercept(self, enabled: bool):
        self._state.intercept = bool(enabled)
        self.state.emit("Intercept ON" if enabled else "Intercept OFF")

    def release(self, message_id: str):
        self._state.action(message_id, "RELEASED")

    def drop(self, message_id: str):
        self._state.action(message_id, "DROPPED")

    def run(self):
        try:
            self.server = _ThreadingHTTPServer((self.host, self.port), _Handler)
            self.server.proxy_app = self
            self.state.emit(f"Proxy listener started on {self.host}:{self.port}")
            self.server.serve_forever(poll_interval=0.2)
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            if self.server:
                try:
                    self.server.server_close()
                except Exception:
                    pass
                self.server = None
            self.state.emit("Proxy listener stopped")

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
            except Exception:
                pass
        self.quit()
        self.wait(1500)
