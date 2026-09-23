from __future__ import annotations

import base64
import difflib
import html
import importlib.util
import json
import math
import re
import time
import urllib.parse
from dataclasses import asdict
from pathlib import Path

import httpx

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QPixmap, QCursor
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QComboBox,
    QCheckBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QFileDialog,
    QMenu,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.version import __version__
from core.analyzer import AnalysisResult, WebAnalyzer
from core.chrome_capture import CapturedTransaction, ChromeCaptureThread, find_free_port, launch_chrome
from core.http_proxy import LocalHttpProxy, ProxyMessage
from core.http_tools import (parse_http_request as parse_http_request_core, request_to_raw, response_to_raw, is_in_scope, ScopeRule, hash_text, decode_jwt)
from core.project_store import export_project, import_project
from core.payloads import PAYLOAD_CATALOG

ROOT = Path(__file__).resolve().parents[1]
LOGO = ROOT / "assets" / "kconk_logo.png"
EXTENSIONS = ROOT / "extensions"

# Fixed reference canvas. Window resize never changes the geometry inside it.
DESIGN_WIDTH = 1500
DESIGN_HEIGHT = 920
TOPBAR_HEIGHT = 76
STATUS_HEIGHT = 38
BODY_HEIGHT = DESIGN_HEIGHT - TOPBAR_HEIGHT - STATUS_HEIGHT
SIDEBAR_WIDTH = 330
CONTENT_WIDTH = DESIGN_WIDTH - SIDEBAR_WIDTH

BG = "#06110d"
BG2 = "#081711"
PANEL = "#0b2118"
PANEL2 = "#091a13"
LINE = "#284437"
LINE2 = "#1b3328"
TEXT = "#eee5cc"
TEXT2 = "#b8b7a1"
MUTED = "#7f8f83"
GOLD = "#d8b56a"
GOLD2 = "#f0d18b"
GREEN = "#79a47d"
RED = "#d8796b"
BLUE = "#80b5c3"

STYLE = f"""
QMainWindow, QWidget {{ background:{BG}; color:{TEXT}; font-family:'DejaVu Sans'; }}
QLabel {{ background:transparent; }}
QScrollArea {{ border:0; background:{BG}; }}
QScrollBar:vertical {{ width:11px; background:#06110d; border-left:1px solid {LINE}; }}
QScrollBar::handle:vertical {{ background:#294938; border-radius:5px; min-height:45px; }}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{ height:0; }}
QScrollBar:horizontal {{ height:11px; background:#06110d; border-top:1px solid {LINE}; }}
QScrollBar::handle:horizontal {{ background:#294938; border-radius:5px; min-width:45px; }}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal {{ width:0; }}
QFrame#topbar {{ background:#07130f; border-bottom:1px solid {LINE}; }}
QFrame#sidebar {{ background:#06140f; border-right:1px solid {LINE}; }}
QFrame#content {{ background:{BG}; }}
QFrame#card {{ background:{PANEL}; border:1px solid {LINE}; border-radius:12px; }}
QFrame#subcard {{ background:{PANEL2}; border:1px solid {LINE2}; border-radius:10px; }}
QFrame#logopane {{ background:qradialgradient(cx:.5,cy:.45,radius:.75,stop:0 #173a29,stop:.5 #0b2418,stop:1 #06130e); border:1px solid {LINE}; border-radius:14px; }}
QLineEdit,QPlainTextEdit,QComboBox,QTableWidget,QTreeWidget,QListWidget {{ background:#061711; border:1px solid {LINE}; border-radius:8px; padding:7px; color:{TEXT}; selection-background-color:#1f4432; }}
QHeaderView::section {{ background:#0d251a; color:#a8ad9f; border:0; border-bottom:1px solid {LINE}; padding:9px; font-weight:700; }}
QTableWidget {{ gridline-color:#173126; }}
QPushButton {{ background:#0d261b; border:1px solid {LINE}; border-radius:8px; padding:8px 13px; color:{TEXT}; font-weight:700; }}
QPushButton:hover {{ background:#173728; border-color:{GOLD}; }}
QPushButton#primary {{ background:#c9a661; color:#182017; border-color:#e1c278; }}
QPushButton#danger {{ background:#341b18; color:#f0b1a6; border-color:#66352e; }}
QPushButton#nav {{ text-align:left; background:transparent; border:1px solid transparent; padding:10px 12px; color:{TEXT2}; }}
QPushButton#nav:hover {{ background:#102a1e; color:{TEXT}; }}
QPushButton#navActive {{ text-align:left; background:#17372a; border:1px solid #3b5d49; padding:10px 12px; color:{GOLD2}; }}
QPushButton#topnav {{ background:transparent; border:0; border-bottom:2px solid transparent; border-radius:0; padding:14px 8px 12px; color:#9fa696; font-size:10px; }}
QPushButton#topnav:hover {{ color:{TEXT}; }}
QPushButton#topnavActive {{ background:transparent; border:0; border-bottom:2px solid {GOLD2}; border-radius:0; padding:14px 8px 12px; color:{GOLD2}; font-size:10px; }}
QTabBar::tab {{ background:#0b1b14; border:1px solid {LINE}; padding:8px 14px; margin-right:4px; border-radius:7px; color:{TEXT2}; }}
QTabBar::tab:selected {{ background:#163629; color:{GOLD2}; border-color:#3d604b; }}
QSplitter::handle {{ background:#193428; }}
"""


def label(text: str, size: int = 12, color: str = TEXT, bold: bool = False) -> QLabel:
    w = QLabel(text)
    w.setStyleSheet(f"font-size:{size}px;color:{color};font-weight:{'800' if bold else '400'};")
    return w


def add_spacer(layout: QHBoxLayout | QVBoxLayout) -> None:
    layout.addStretch(1)


def response_reason(status: int) -> str:
    return {200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently", 302: "Found", 304: "Not Modified", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests", 500: "Internal Server Error", 502: "Bad Gateway"}.get(status, "")


class AnalysisWorker(QThread):
    done = Signal(object)
    failed = Signal(str)
    line = Signal(str)

    def __init__(self, target: str, records: list[CapturedTransaction]):
        super().__init__()
        self.target = target
        self.records = records

    def run(self):
        try:
            analyzer = WebAnalyzer(timeout=12, max_pages=30)
            if self.records:
                result = analyzer.run_from_history(self.records, self.target, self.line.emit)
            else:
                result = analyzer.run(self.target, self.line.emit)
            self.done.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class HttpReplayWorker(QThread):
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, method: str, url: str, headers: dict[str, str], body: str, http_version: str = "AUTO"):
        super().__init__()
        self.method = method.upper()
        self.url = url
        self.headers = headers
        self.body = body
        self.http_version = http_version
        self.stop_requested = False

    def run(self):
        try:
            started = time.perf_counter()
            with httpx.Client(
                timeout=httpx.Timeout(connect=5.0, read=8.0, write=5.0, pool=5.0),
                follow_redirects=False,
                verify=False,
                http2=self.http_version in {"AUTO", "HTTP/2"},
            ) as client:
                with client.stream(self.method, self.url, headers=self.headers, content=self.body.encode("utf-8") if self.body else None) as r:
                    chunks = []
                    for chunk in r.iter_bytes():
                        if self.stop_requested:
                            return
                        chunks.append(chunk)
                    elapsed = int((time.perf_counter() - started) * 1000)
                    content = b"".join(chunks)
                    if self.http_version == "HTTP/2" and r.http_version != "HTTP/2":
                        raise RuntimeError(f"HTTP/2 requested, but server negotiated {r.http_version}")
                    status = f"{r.status_code} {r.reason_phrase}"
                    headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
                    body_text = content.decode("utf-8", errors="replace")
                    raw = f"{r.http_version} {r.status_code} {r.reason_phrase}\n{headers_text}\n\n{body_text}"
                    self.done.emit((raw, status, elapsed, len(content), str(r.url)))
        except Exception as exc:
            if not self.stop_requested:
                self.failed.emit(str(exc))


class IntruderWorker(QThread):
    row = Signal(object)
    done = Signal()
    failed = Signal(str)

    def __init__(self, method: str, url: str, headers: dict[str, str], body: str, parameter: str, payloads: list[str]):
        super().__init__()
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.parameter = parameter
        self.payloads = payloads[:50]
        self.stop_requested = False

    @staticmethod
    def mutate(url: str, body: str, parameter: str, payload: str) -> tuple[str, str]:
        parts = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        replaced = False
        out = []
        for k, v in query:
            if k == parameter:
                out.append((k, payload))
                replaced = True
            else:
                out.append((k, v))
        if replaced:
            new_query = urllib.parse.urlencode(out, doseq=True)
            return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)), body
        if "=" in body and parameter:
            form = urllib.parse.parse_qsl(body, keep_blank_values=True)
            new_form = []
            for k, v in form:
                if k == parameter:
                    new_form.append((k, payload)); replaced = True
                else:
                    new_form.append((k, v))
            if replaced:
                return url, urllib.parse.urlencode(new_form, doseq=True)
        return url, body.replace(f"{{{{{parameter}}}}}", payload) if f"{{{{{parameter}}}}}" in body else body.replace(parameter, payload, 1)

    def run(self):
        try:
            with httpx.Client(timeout=8, follow_redirects=False, verify=False) as client:
                for payload in self.payloads:
                    if self.stop_requested:
                        break
                    url, body = self.mutate(self.url, self.body, self.parameter.strip(), payload)
                    started = time.perf_counter()
                    r = client.request(self.method, url, headers=self.headers, content=body.encode() if body else None)
                    elapsed = int((time.perf_counter() - started) * 1000)
                    content = r.content
                    snippet = content[:180].decode("utf-8", errors="replace").replace("\n", " ")
                    self.row.emit({
                        "payload": payload,
                        "status": r.status_code,
                        "length": len(content),
                        "time": elapsed,
                        "url": url,
                        "snippet": snippet,
                    })
                self.done.emit()
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    NAV = ["DASHBOARD", "TARGET", "PROXY", "INTRUDER", "REPEATER", "COLLABORATOR", "SEQUENCER", "DECODER", "COMPARER", "LOGGER", "ORGANIZER", "EXTENSIONS", "DISCOVER"]

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"KCONK Suite v{__version__}")
        self.resize(1500, 920)
        self.setStyleSheet(STYLE)

        self.records: list[CapturedTransaction] = []
        self.record_by_request: dict[str, CapturedTransaction] = {}
        self.events: list[str] = []
        self.saved_requests: list[dict] = []
        self.current_result: AnalysisResult | None = None
        self.capture: ChromeCaptureThread | None = None
        self.chrome_process = None
        self.chrome_profile = None
        self.analysis_worker: AnalysisWorker | None = None
        self.repeater_worker: HttpReplayWorker | None = None
        self.intruder_worker: IntruderWorker | None = None
        self.local_proxy: LocalHttpProxy | None = None
        self.proxy_messages: dict[str, ProxyMessage] = {}
        self.scope_rules: list[ScopeRule] = []
        self.proxy_history_filter = ""

        viewport = QScrollArea()
        viewport.setObjectName("viewport")
        viewport.setWidgetResizable(False)
        viewport.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        canvas = QWidget()
        canvas.setFixedSize(DESIGN_WIDTH, DESIGN_HEIGHT)
        canvas_layout = QVBoxLayout(canvas)
        canvas_layout.setContentsMargins(0, 0, 0, 0)
        canvas_layout.setSpacing(0)

        canvas_layout.addWidget(self.build_topbar())
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self.build_sidebar())
        self.stack = QStackedWidget()
        self.stack.setFixedSize(CONTENT_WIDTH, BODY_HEIGHT)
        body.addWidget(self.stack)
        body_widget = QWidget()
        body_widget.setFixedSize(DESIGN_WIDTH, BODY_HEIGHT)
        body_widget.setLayout(body)
        canvas_layout.addWidget(body_widget)
        canvas_layout.addWidget(self.build_statusbar())
        viewport.setWidget(canvas)
        self.setCentralWidget(viewport)

        self.pages = {}
        for name, builder in [
            ("DASHBOARD", self.page_dashboard),
            ("TARGET", self.page_target),
            ("PROXY", self.page_proxy),
            ("INTRUDER", self.page_intruder),
            ("REPEATER", self.page_repeater),
            ("COLLABORATOR", self.page_collaborator),
            ("SEQUENCER", self.page_sequencer),
            ("DECODER", self.page_decoder),
            ("COMPARER", self.page_comparer),
            ("LOGGER", self.page_logger),
            ("ORGANIZER", self.page_organizer),
            ("EXTENSIONS", self.page_extensions),
            ("DISCOVER", self.page_discover),
        ]:
            p = builder()
            self.pages[name] = p
            self.stack.addWidget(p)

        self.active_nav = "DASHBOARD"
        self.update_sidebar("DASHBOARD")
        self.show_page("DASHBOARD")
        self.log_event("KCONK Suite initialized")

    # ------------------------------------------------------------------ layout
    def build_topbar(self) -> QFrame:
        bar = QFrame(); bar.setObjectName("topbar"); bar.setFixedSize(DESIGN_WIDTH, TOPBAR_HEIGHT)
        outer = QHBoxLayout(bar); outer.setContentsMargins(16, 0, 16, 0); outer.setSpacing(6)
        brand = QHBoxLayout(); brand.setSpacing(9)
        icon = QLabel(); icon.setFixedSize(42, 42); icon.setAlignment(Qt.AlignCenter)
        pix = QPixmap(str(LOGO))
        if not pix.isNull():
            icon.setPixmap(pix.scaled(39, 39, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        brand.addWidget(icon)
        brand_box = QVBoxLayout(); brand_box.setSpacing(0)
        brand_box.addWidget(label("KCONK Suite", 17, GOLD2, True))
        brand_box.addWidget(label(f"Community Edition v{__version__}", 9, TEXT2))
        brand.addLayout(brand_box)
        brand_widget = QWidget(); brand_widget.setFixedWidth(235); brand_widget.setLayout(brand); outer.addWidget(brand_widget)

        widths = [78, 62, 57, 74, 76, 103, 86, 73, 78, 61, 78, 85, 75]
        self.top_buttons = {}
        for name, width in zip(self.NAV, widths):
            b = QPushButton(name); b.setObjectName("topnav"); b.setFixedWidth(width)
            b.clicked.connect(lambda _, n=name: self.show_page(n)); self.top_buttons[name] = b; outer.addWidget(b)
        outer.addStretch(1)
        for glyph, handler in [("◉", lambda: self.new_live_capture()), ("☾", lambda: self.log_event("UI theme: dark")), ("⚙", lambda: self.project_menu())]:
            b = QPushButton(glyph); b.setFixedSize(34, 34); b.setStyleSheet(f"QPushButton{{border:0;background:transparent;color:{GOLD2};font-size:17px;}}QPushButton:hover{{background:#10261a;border-radius:8px;}}"); b.clicked.connect(handler); outer.addWidget(b)
        return bar

    def build_sidebar(self) -> QFrame:
        side = QFrame(); side.setObjectName("sidebar"); side.setFixedSize(SIDEBAR_WIDTH, BODY_HEIGHT)
        l = QVBoxLayout(side); l.setContentsMargins(18, 17, 18, 14); l.setSpacing(10)
        head = QHBoxLayout(); head.addWidget(label("Tasks", 20, TEXT, True)); add_spacer(head)
        for glyph, handler in [("◫", lambda: self.new_scan()), ("⚙", lambda: self.show_page("EXTENSIONS")), ("?", lambda: QMessageBox.information(self, "KCONK Suite", "KCONK Suite functional workbench."))]:
            b = QPushButton(glyph); b.setFixedSize(31, 31); b.setStyleSheet(f"QPushButton{{border:0;background:transparent;color:{TEXT2};font-size:15px;}}QPushButton:hover{{color:{GOLD2};}}"); b.clicked.connect(handler); head.addWidget(b)
        l.addLayout(head)

        actions = QHBoxLayout(); actions.setSpacing(8)
        b1 = QPushButton("New scan"); b1.setFixedWidth(112); b1.clicked.connect(self.new_scan)
        b2 = QPushButton("New live task"); b2.setObjectName("primary"); b2.setFixedWidth(126); b2.clicked.connect(self.new_live_capture)
        actions.addWidget(b1); actions.addWidget(b2); actions.addStretch(1); l.addLayout(actions)

        self.task_search = QLineEdit(); self.task_search.setPlaceholderText("Search tasks / modules"); self.task_search.setFixedHeight(37); self.task_search.textChanged.connect(self.filter_tasks); l.addWidget(self.task_search)
        self.task_list = QListWidget(); self.task_list.setFixedHeight(300); self.task_list.itemClicked.connect(self.sidebar_task_clicked)
        l.addWidget(self.task_list)

        logo_card = QFrame(); logo_card.setObjectName("logopane"); logo_card.setFixedWidth(294)
        lv = QVBoxLayout(logo_card); lv.setContentsMargins(14, 12, 14, 14); lv.setSpacing(7)
        lv.addWidget(label("KCONK", 11, GOLD, True), 0, Qt.AlignHCenter)
        logo_view = QLabel(); logo_view.setAlignment(Qt.AlignCenter)
        pix = QPixmap(str(LOGO))
        if not pix.isNull(): logo_view.setPixmap(pix.scaled(235, 235, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        lv.addWidget(logo_view, 1)
        lv.addWidget(label("Security through curiosity", 10, TEXT2, True), 0, Qt.AlignHCenter)
        self.task_hint = label("Capture traffic, inspect it, then move requests into Repeater or Intruder.", 10, MUTED)
        self.task_hint.setWordWrap(True); self.task_hint.setAlignment(Qt.AlignCenter); lv.addWidget(self.task_hint)
        l.addWidget(logo_card, 1)
        return side

    def build_statusbar(self) -> QFrame:
        bar = QFrame(); bar.setObjectName("topbar"); bar.setFixedSize(DESIGN_WIDTH, STATUS_HEIGHT)
        l = QHBoxLayout(bar); l.setContentsMargins(16, 0, 16, 0); l.setSpacing(14)
        self.status_label = label("Ready", 10, TEXT2)
        l.addWidget(label("Event log", 10, TEXT2, True)); l.addWidget(self.status_label, 1)
        l.addWidget(label("Captured:", 10, MUTED)); self.status_count = label("0", 10, GOLD2, True); l.addWidget(self.status_count)
        l.addWidget(label("KCONK", 10, GOLD, True)); return bar

    # ------------------------------------------------------------------ common
    def page_frame(self, title: str, subtitle: str = "") -> tuple[QFrame, QVBoxLayout]:
        wrapper = QFrame(); wrapper.setObjectName("content"); wrapper.setFixedSize(CONTENT_WIDTH, BODY_HEIGHT)
        l = QVBoxLayout(wrapper); l.setContentsMargins(22, 18, 20, 14); l.setSpacing(12)
        head = QHBoxLayout(); head.addWidget(label("◇", 24, GOLD2, True))
        tb = QVBoxLayout(); tb.setSpacing(1); tb.addWidget(label(title, 21, TEXT, True)); tb.addWidget(label(subtitle, 10, MUTED))
        hw = QWidget(); hw.setFixedWidth(760); hw.setLayout(tb); head.addWidget(hw); add_spacer(head); head.addWidget(label("K C O N K", 17, GOLD2, True)); l.addLayout(head)
        return wrapper, l

    def card(self, w: int, h: int | None = None) -> QFrame:
        f = QFrame(); f.setObjectName("card"); f.setFixedWidth(w)
        if h is not None: f.setFixedHeight(h)
        return f

    def show_page(self, name: str):
        if name not in self.pages: return
        self.active_nav = name
        self.stack.setCurrentWidget(self.pages[name])
        self.update_sidebar(name)
        for n, b in self.top_buttons.items():
            b.setObjectName("topnavActive" if n == name else "topnav")
            b.style().unpolish(b); b.style().polish(b)
        self.set_status(f"Module: {name.title()}")

    def update_sidebar(self, module: str):
        self.task_list.blockSignals(True); self.task_list.clear()
        task_map = {
            "DASHBOARD": ["Live passive crawl from Proxy", "Recent HTTP history", "Request / response inspector"],
            "TARGET": ["Scope", "Site map", "Target analysis", "Discovered technologies", "Secrets / JWT"],
            "PROXY": ["Live capture", "HTTP history", "Intercept queue", "Send to Repeater"],
            "INTRUDER": ["Attack setup", "Payload positions", "Results", "Response comparison"],
            "REPEATER": ["Request editor", "Response viewer", "History", "Protocol selector"],
            "COLLABORATOR": ["Canary generator", "Correlation notes"],
            "SEQUENCER": ["Token samples", "Entropy", "Character distribution"],
            "DECODER": ["Base64", "URL", "Hex", "HTML", "JWT"],
            "COMPARER": ["Request A", "Request B", "Diff"],
            "LOGGER": ["Traffic", "Analysis", "Repeater", "Intruder"],
            "ORGANIZER": ["Saved requests", "Collections", "Notes"],
            "EXTENSIONS": ["Local extensions", "Load extension", "Extension API"],
            "DISCOVER": ["Crawler", "Forms", "Technologies", "Passive findings", "Payload catalog"],
        }
        for item in task_map.get(module, []): self.task_list.addItem(QListWidgetItem(item))
        self.task_hint.setText({"DASHBOARD":"Capture browser traffic and move interesting requests into dedicated tools.","TARGET":"Define scope and build a site map before focused testing.","PROXY":"Use Chromium CDP capture to inspect application traffic.","INTRUDER":"Replay controlled payloads against a selected parameter.","REPEATER":"Edit one HTTP request and send it repeatedly.","COLLABORATOR":"Generate local canaries for correlation workflows.","SEQUENCER":"Evaluate token sample randomness without sending traffic.","DECODER":"Transform encoded values used during request analysis.","COMPARER":"Diff two artifacts side by side.","LOGGER":"Review a unified event history.","ORGANIZER":"Save and reuse request templates.","EXTENSIONS":"Load local Python modules exposing register(app).","DISCOVER":"Run the existing CTF-oriented passive and controlled analyzer."}.get(module,""))
        self.task_list.blockSignals(False)

    def filter_tasks(self, text: str):
        q = text.strip().lower()
        for i in range(self.task_list.count()): self.task_list.item(i).setHidden(q not in self.task_list.item(i).text().lower()) if q else self.task_list.item(i).setHidden(False)

    def sidebar_task_clicked(self, item: QListWidgetItem):
        text = item.text().lower()
        actions = {"repeater": "REPEATER", "scope":"TARGET", "site map":"TARGET", "live capture":"PROXY", "http history":"PROXY", "payload":"INTRUDER", "token":"SEQUENCER", "entropy":"SEQUENCER", "canary":"COLLABORATOR", "diff":"COMPARER", "saved requests":"ORGANIZER", "local extensions":"EXTENSIONS", "technologies":"DISCOVER", "crawler":"DISCOVER"}
        for key, page in actions.items():
            if key in text: self.show_page(page); break

    def set_status(self, text: str):
        self.status_label.setText(text); self.status_count.setText(str(len(self.records)))

    def log_event(self, message: str):
        stamp = time.strftime("%H:%M:%S")
        self.events.append(f"[{stamp}] {message}")
        self.status_label.setText(message)
        if hasattr(self, "logger_table"):
            self.logger_table.insertRow(0); self.logger_table.setItem(0, 0, QTableWidgetItem(stamp)); self.logger_table.setItem(0, 1, QTableWidgetItem(message))

    def new_scan(self):
        self.show_page("TARGET"); self.scope_input.setFocus(); self.log_event("New target analysis task")

    def new_live_capture(self):
        target = self.proxy_target.text().strip() if hasattr(self, "proxy_target") else ""
        if not target:
            target = self.dashboard_target.text().strip() if hasattr(self, "dashboard_target") else ""
        if not target:
            target = self.scope_input.text().strip() if hasattr(self, "scope_input") else ""
        if not target:
            target = "https://example.com"
        if hasattr(self, "dashboard_target"):
            self.dashboard_target.setText(target)
        if not re.match(r"^https?://", target, re.I):
            target = "https://" + target
        try:
            # Route the browser through the local listener when it is active.
            if not self.local_proxy:
                self.start_proxy_listener()
                time.sleep(0.15)
            self.start_capture(target)
            self.show_page("PROXY")
        except Exception as exc:
            QMessageBox.warning(self, "Capture failed", str(exc))

    # ------------------------------------------------------------------ capture
    def start_capture(self, target: str):
        self.stop_capture(False)
        self.stop_proxy_listener()
        self.records.clear(); self.record_by_request.clear()
        self.proxy_table.setRowCount(0); self.dashboard_table.setRowCount(0)
        port = find_free_port()
        proxy_port = self.local_proxy.port if self.local_proxy and self.local_proxy.isRunning() else None
        proc, _port, profile = launch_chrome(target, port, proxy_port)
        self.chrome_process = proc; self.chrome_profile = profile
        self.capture = ChromeCaptureThread(port, target, self)
        self.capture.transaction.connect(self.on_transaction)
        self.capture.updated.connect(self.on_transaction_updated)
        self.capture.state.connect(self.set_status)
        self.capture.error.connect(lambda msg: self.log_event(f"Capture error: {msg}"))
        self.capture.start()
        self.log_event(f"Live capture started: {target}")

    def stop_capture(self, announce: bool = True):
        if self.capture:
            try: self.capture.stop(); self.capture.wait(1200)
            except Exception: pass
            self.capture = None
        if self.chrome_process:
            try: self.chrome_process.terminate()
            except Exception: pass
            self.chrome_process = None
        if announce: self.log_event("Live capture stopped")

    @staticmethod
    def request_text(rec: CapturedTransaction) -> str:
        path = urllib.parse.urlsplit(rec.url)
        target = urllib.parse.urlunsplit(("", "", path.path or "/", path.query, "")) or "/"
        lines = [f"{rec.method} {target} HTTP/1.1"]
        for k, v in rec.request_headers.items():
            if k.startswith(":"): continue
            lines.append(f"{k}: {v}")
        body = rec.request_body or ""
        return "\n".join(lines) + ("\n\n" + body if body else "")

    @staticmethod
    def response_text(rec: CapturedTransaction) -> str:
        status = rec.status or 0
        reason = rec.status_text or response_reason(status)
        version = "HTTP/1.1"
        lines = [f"{version} {status} {reason}".strip()]
        for k, v in rec.response_headers.items():
            if k.startswith(":"): continue
            lines.append(f"{k}: {v}")
        body = rec.response_body or ""
        return "\n".join(lines) + ("\n\n" + body if body else "")

    def on_transaction(self, rec: CapturedTransaction):
        self.record_by_request[rec.request_id] = rec
        if rec.request_id not in {r.request_id for r in self.records}:
            self.records.append(rec)
            self.fill_traffic_row(rec)
            self.log_event(f"{rec.method} {rec.url}")

    def on_transaction_updated(self, rec: CapturedTransaction):
        self.record_by_request[rec.request_id] = rec
        self.refresh_traffic_row(rec)
        self.status_count.setText(str(len(self.records)))
        if hasattr(self, "dashboard_selected_request"):
            row = self.proxy_table.currentRow()
            if row >= 0: self.show_record_at_row(row)

    def fill_traffic_row(self, rec: CapturedTransaction):
        for table in (self.proxy_table, self.dashboard_table):
            row = table.rowCount(); table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(rec.method)); table.setItem(row, 1, QTableWidgetItem(rec.url)); table.setItem(row, 2, QTableWidgetItem(str(rec.status or "—"))); table.setItem(row, 3, QTableWidgetItem(str(rec.response_size))); table.setItem(row, 4, QTableWidgetItem(rec.mime_type or "—")); table.setItem(row, 5, QTableWidgetItem(f"{rec.duration_ms} ms")); table.item(row, 1).setData(Qt.UserRole, rec.request_id)

    def refresh_traffic_row(self, rec: CapturedTransaction):
        for table in (self.proxy_table, self.dashboard_table):
            for row in range(table.rowCount()):
                item = table.item(row, 1)
                if item and item.data(Qt.UserRole) == rec.request_id:
                    table.item(row, 0).setText(rec.method); table.item(row, 2).setText(str(rec.status or "—")); table.item(row, 3).setText(str(rec.response_size)); table.item(row, 4).setText(rec.mime_type or "—"); table.item(row, 5).setText(f"{rec.duration_ms} ms")
                    break

    def show_record_at_row(self, row: int):
        if row < 0: return
        item = self.proxy_table.item(row, 1); rid = item.data(Qt.UserRole) if item else None
        rec = self.record_by_request.get(rid)
        if rec:
            self.proxy_request.setPlainText(self.request_text(rec)); self.proxy_response.setPlainText(self.response_text(rec)); self.dashboard_request.setPlainText(self.request_text(rec)); self.dashboard_response.setPlainText(self.response_text(rec))

    def selected_record(self) -> CapturedTransaction | None:
        for table in (self.proxy_table, self.dashboard_table):
            row = table.currentRow()
            if row >= 0:
                item = table.item(row, 1)
                if item:
                    rec = self.record_by_request.get(item.data(Qt.UserRole))
                    if rec:
                        return rec
        return self.records[-1] if self.records else None

    # ---------------------------------------------------------------- dashboard
    def page_dashboard(self) -> QWidget:
        w, l = self.page_frame("1. Live passive crawl from Proxy (all traffic)", "Dashboard • traffic-driven workflow")
        top = self.card(1128, 86); tl = QHBoxLayout(top); tl.setContentsMargins(16, 12, 16, 12); tl.setSpacing(10)
        tb = QVBoxLayout(); tb.addWidget(label("TARGET", 10, MUTED, True)); self.dashboard_target = QLineEdit(); self.dashboard_target.setPlaceholderText("https://target.example"); self.dashboard_target.setFixedWidth(540); tb.addWidget(self.dashboard_target); tl.addLayout(tb)
        b = QPushButton("Open in capture"); b.setObjectName("primary"); b.setFixedWidth(140); b.clicked.connect(lambda: self.new_live_capture()); tl.addWidget(b); add_spacer(tl); self.dashboard_mode = label("Proxy (all traffic)", 11, GOLD2, True); tl.addWidget(self.dashboard_mode)
        l.addWidget(top)

        cols = QHBoxLayout(); cols.setSpacing(14)
        left = self.card(560, 650); lv = QVBoxLayout(left); lv.setContentsMargins(18, 16, 18, 16); lv.addWidget(label("Items added to site map", 13, TEXT, True)); self.dashboard_table = self.make_traffic_table(); self.dashboard_table.itemSelectionChanged.connect(lambda: self.show_dashboard_row()); lv.addWidget(self.dashboard_table, 1)
        dash_detail = QSplitter(Qt.Horizontal); dash_detail.setFixedHeight(180); self.dashboard_request = QPlainTextEdit(); self.dashboard_request.setReadOnly(True); self.dashboard_response = QPlainTextEdit(); self.dashboard_response.setReadOnly(True); dash_detail.addWidget(self.dashboard_request); dash_detail.addWidget(self.dashboard_response); dash_detail.setSizes([270,270]); lv.addWidget(dash_detail)
        right = QVBoxLayout(); cfg = self.card(554, 220); cl = QVBoxLayout(cfg); cl.setContentsMargins(18, 16, 18, 16); cl.addWidget(label("Task configuration", 13, TEXT, True)); cl.addWidget(label("Task type:   Live passive crawl", 11, TEXT2)); cl.addWidget(label("Scope:       Proxy (all traffic)", 11, TEXT2)); cl.addWidget(label("Configuration: Add links / same-domain traffic / suite scope.", 11, TEXT2)); stop = QPushButton("Stop capture"); stop.setObjectName("danger"); stop.clicked.connect(lambda: self.stop_capture(True)); cl.addWidget(stop, 0, Qt.AlignLeft); right.addWidget(cfg)
        prog = self.card(554, 190); pl = QVBoxLayout(prog); pl.setContentsMargins(18, 16, 18, 16); pl.addWidget(label("Task progress", 13, TEXT, True)); self.dashboard_progress = label("Site map items added: 0\nResponses processed: 0\nResponses queued: 0", 11, TEXT2); pl.addWidget(self.dashboard_progress); right.addWidget(prog)
        log = self.card(554, 220); ll = QVBoxLayout(log); ll.setContentsMargins(18, 16, 18, 16); ll.addWidget(label("Task log", 13, TEXT, True)); self.dashboard_log = QPlainTextEdit(); self.dashboard_log.setReadOnly(True); ll.addWidget(self.dashboard_log); right.addWidget(log)
        cols.addWidget(left); rw = QWidget(); rw.setFixedWidth(554); rw.setLayout(right); cols.addWidget(rw); l.addLayout(cols); return w

    def show_dashboard_row(self):
        row = self.dashboard_table.currentRow()
        if row < 0: return
        item = self.dashboard_table.item(row, 1); rid = item.data(Qt.UserRole) if item else None; rec = self.record_by_request.get(rid)
        if rec:
            self.dashboard_request.setPlainText(self.request_text(rec)); self.dashboard_response.setPlainText(self.response_text(rec))

    def make_traffic_table(self) -> QTableWidget:
        t = QTableWidget(0, 6); t.setHorizontalHeaderLabels(["METHOD", "URL", "STATUS", "LENGTH", "MIME TYPE", "TIME"]); t.setSelectionBehavior(QAbstractItemView.SelectRows); t.setSelectionMode(QAbstractItemView.SingleSelection); t.setColumnWidth(0, 75); t.setColumnWidth(1, 280); t.setColumnWidth(2, 70); t.setColumnWidth(3, 80); t.setColumnWidth(4, 120); t.setColumnWidth(5, 80)
        t.setContextMenuPolicy(Qt.CustomContextMenu); t.customContextMenuRequested.connect(lambda pos, table=t: self.traffic_context_menu(table, pos))
        return t

    # --------------------------------------------------------------- target
    def page_target(self) -> QWidget:
        w, l = self.page_frame("Target", "Scope definition and site-map reconnaissance")
        row = QHBoxLayout(); scope = self.card(1128, 72); sl = QHBoxLayout(scope); sl.setContentsMargins(14, 12, 14, 12); sl.addWidget(label("SCOPE", 10, MUTED, True)); self.scope_input = QLineEdit("127.0.0.1"); self.scope_input.setFixedWidth(290); sl.addWidget(self.scope_input); add_btn = QPushButton("Add scope"); add_btn.clicked.connect(self.add_scope); sl.addWidget(add_btn); analyze = QPushButton("Analyze target"); analyze.setObjectName("primary"); analyze.clicked.connect(self.start_analysis); sl.addWidget(analyze); stop = QPushButton("Stop"); stop.clicked.connect(self.stop_analysis); sl.addWidget(stop); add_spacer(sl); sl.addWidget(label("Explicit targets only", 10, GOLD, True)); row.addWidget(scope); l.addLayout(row)
        grid = QHBoxLayout(); grid.setSpacing(14)
        site = self.card(700, 650); sv = QVBoxLayout(site); sv.setContentsMargins(16, 16, 16, 16); sv.addWidget(label("Site map", 13, TEXT, True)); self.site_tree = QTreeWidget(); self.site_tree.setHeaderLabels(["Host / URL", "Type"]); self.site_tree.itemDoubleClicked.connect(lambda item,_: self.send_site_item_to_repeater(item)); sv.addWidget(self.site_tree); grid.addWidget(site)
        info = self.card(414, 650); iv = QVBoxLayout(info); iv.setContentsMargins(16, 16, 16, 16); iv.addWidget(label("Target detail", 13, TEXT, True)); self.target_details = QPlainTextEdit(); self.target_details.setReadOnly(True); iv.addWidget(self.target_details); grid.addWidget(info); l.addLayout(grid); return w

    def add_scope(self):
        value = self.scope_input.text().strip()
        if not value:
            return
        pattern = value if "*" in value else (value.rstrip("/") + "*")
        if not re.match(r"^https?://", pattern, re.I):
            pattern = "https://" + pattern
        rule = ScopeRule(pattern=pattern, include=True)
        if rule not in self.scope_rules:
            self.scope_rules.append(rule)
        self.log_event(f"Scope added: {pattern}")
        self.refresh_traffic_filters()

    def start_analysis(self):
        target = self.scope_input.text().strip() or self.dashboard_target.text().strip()
        if not target: QMessageBox.warning(self, "Target", "Enter a target first."); return
        if not re.match(r"^https?://", target, re.I): target = "https://" + target
        if self.analysis_worker and self.analysis_worker.isRunning(): return
        self.analysis_worker = AnalysisWorker(target, self.records)
        self.analysis_worker.done.connect(self.analysis_done); self.analysis_worker.failed.connect(lambda msg: self.log_event(f"Analysis failed: {msg}")); self.analysis_worker.line.connect(lambda msg: self.log_event(msg)); self.analysis_worker.start(); self.set_status(f"Analyzing {target} …")

    def stop_analysis(self):
        if self.analysis_worker and self.analysis_worker.isRunning():
            self.analysis_worker.terminate()
            self.analysis_worker.wait(800)
        self.set_status("Analyzer stopped")
        self.log_event("Analyzer stopped")

    def analysis_done(self, result: AnalysisResult):
        self.current_result = result; self.site_tree.clear()
        for url in result.site_map:
            sp = urllib.parse.urlsplit(url); host = sp.netloc or sp.path; root = QTreeWidgetItem([host, "host"]); leaf = QTreeWidgetItem([url, "URL"]); root.addChild(leaf); self.site_tree.addTopLevelItem(root)
        self.site_tree.expandAll()
        self.target_details.setPlainText(json.dumps({"target":result.target,"scope":[r.pattern for r in self.scope_rules],"requests":len(result.requests),"forms":len(result.forms),"js_files":len(result.js_files),"technologies":result.technologies,"cookies":result.cookies,"secrets":result.secrets,"jwt_tokens":[asdict(x) for x in result.jwt_tokens],"websockets":result.websockets,"findings":len(result.payload_runs)}, indent=2, ensure_ascii=False))
        self.log_event(f"Analysis complete: {len(result.site_map)} URLs, {len(result.payload_runs)} test runs")
        self.show_page("TARGET")

    def send_site_item_to_repeater(self, item: QTreeWidgetItem):
        if item.text(1) != "URL": return
        url = item.text(0); self.prepare_repeater("GET", url, f"GET {urllib.parse.urlsplit(url).path or '/'} HTTP/1.1\nHost: {urllib.parse.urlsplit(url).netloc}"); self.show_page("REPEATER")

    # --------------------------------------------------------------- proxy
    def page_proxy(self) -> QWidget:
        w, l = self.page_frame("Proxy", "HTTP listener, browser capture, intercept and HTTP history")
        toolbar = self.card(1128, 76)
        tl = QHBoxLayout(toolbar); tl.setContentsMargins(14, 10, 14, 10); tl.setSpacing(8)
        tl.addWidget(label("Listener", 10, MUTED, True))
        self.proxy_host = QLineEdit("127.0.0.1"); self.proxy_host.setFixedWidth(125); tl.addWidget(self.proxy_host)
        self.proxy_port = QLineEdit("8080"); self.proxy_port.setFixedWidth(72); tl.addWidget(self.proxy_port)
        start_listener = QPushButton("Start listener"); start_listener.setObjectName("primary"); start_listener.clicked.connect(self.start_proxy_listener); tl.addWidget(start_listener)
        stop_listener = QPushButton("Stop"); stop_listener.setObjectName("danger"); stop_listener.clicked.connect(self.stop_proxy_listener); tl.addWidget(stop_listener)
        self.proxy_intercept = QCheckBox("Intercept HTTP"); self.proxy_intercept.setChecked(False); self.proxy_intercept.stateChanged.connect(lambda state: self.set_proxy_intercept(state != 0)); tl.addWidget(self.proxy_intercept)
        add_spacer(tl)
        self.proxy_target = QLineEdit(); self.proxy_target.setPlaceholderText("https://target.example"); self.proxy_target.setFixedWidth(300); tl.addWidget(self.proxy_target)
        start_browser = QPushButton("Open browser"); start_browser.clicked.connect(lambda: self.new_live_capture()); tl.addWidget(start_browser)
        l.addWidget(toolbar)

        filters = self.card(1128, 48); fl = QHBoxLayout(filters); fl.setContentsMargins(12, 7, 12, 7); fl.addWidget(label("Search", 10, MUTED, True))
        self.proxy_filter = QLineEdit(); self.proxy_filter.setPlaceholderText("host, URL, method, status…"); self.proxy_filter.setFixedWidth(420); self.proxy_filter.textChanged.connect(self.refresh_traffic_filters); fl.addWidget(self.proxy_filter)
        self.proxy_scope_only = QCheckBox("Show in-scope only"); self.proxy_scope_only.stateChanged.connect(self.refresh_traffic_filters); fl.addWidget(self.proxy_scope_only)
        clear = QPushButton("Clear history"); clear.clicked.connect(self.clear_traffic_history); fl.addWidget(clear); add_spacer(fl); fl.addWidget(label("HTTP listener handles cleartext HTTP; CDP handles decrypted browser HTTPS.", 9, MUTED)); l.addWidget(filters)

        tabs = QTabWidget(); tabs.setFixedSize(1128, 610)
        history = QWidget(); hv = QVBoxLayout(history); hv.setContentsMargins(6, 8, 6, 6)
        self.proxy_table = self.make_traffic_table(); self.proxy_table.itemSelectionChanged.connect(self.show_proxy_selection); hv.addWidget(self.proxy_table, 1)
        detail = QSplitter(Qt.Horizontal); detail.setFixedHeight(285)
        req_card = self.card(548, 280); rv = QVBoxLayout(req_card); rv.setContentsMargins(12, 12, 12, 12); rv.addWidget(label("Request", 12, TEXT, True)); self.proxy_request = QPlainTextEdit(); rv.addWidget(self.proxy_request); detail.addWidget(req_card)
        res_card = self.card(548, 280); sv = QVBoxLayout(res_card); sv.setContentsMargins(12, 12, 12, 12); sv.addWidget(label("Response", 12, TEXT, True)); self.proxy_response = QPlainTextEdit(); sv.addWidget(self.proxy_response); detail.addWidget(res_card)
        detail.setSizes([548, 548]); hv.addWidget(detail)
        tabs.addTab(history, "HTTP history")

        intercept = QWidget(); iv = QVBoxLayout(intercept); iv.setContentsMargins(8, 8, 8, 8)
        self.proxy_intercept_table = QTableWidget(0, 6); self.proxy_intercept_table.setHorizontalHeaderLabels(["ID", "METHOD", "URL", "STATE", "CLIENT", "TIME"]); self.proxy_intercept_table.setSelectionBehavior(QAbstractItemView.SelectRows); self.proxy_intercept_table.setColumnWidth(0, 90); self.proxy_intercept_table.setColumnWidth(1, 70); self.proxy_intercept_table.setColumnWidth(2, 430); self.proxy_intercept_table.setColumnWidth(3, 90); self.proxy_intercept_table.setColumnWidth(4, 160); self.proxy_intercept_table.setColumnWidth(5, 90); iv.addWidget(self.proxy_intercept_table, 1)
        buttons = QHBoxLayout(); rel = QPushButton("Forward selected"); rel.setObjectName("primary"); rel.clicked.connect(self.release_selected_intercept); drop = QPushButton("Drop selected"); drop.setObjectName("danger"); drop.clicked.connect(self.drop_selected_intercept); torep = QPushButton("Send to Repeater"); torep.clicked.connect(self.intercept_to_repeater); toint = QPushButton("Send to Intruder"); toint.clicked.connect(self.intercept_to_intruder); buttons.addWidget(rel); buttons.addWidget(drop); buttons.addWidget(torep); buttons.addWidget(toint); add_spacer(buttons); iv.addLayout(buttons)
        tabs.addTab(intercept, "Intercept")
        l.addWidget(tabs)
        return w

    # -------------------------------------------------------------- local proxy
    def start_proxy_listener(self):
        if self.local_proxy and self.local_proxy.isRunning():
            return
        try:
            host = self.proxy_host.text().strip() or "127.0.0.1"
            port = int(self.proxy_port.text().strip())
            if not (1 <= port <= 65535):
                raise ValueError("Port must be 1-65535")
            self.local_proxy = LocalHttpProxy(host, port, self)
            self.local_proxy.message.connect(self.on_proxy_message)
            self.local_proxy.response.connect(self.on_proxy_response)
            self.local_proxy.error.connect(lambda m: self.log_event(f"Proxy listener error: {m}"))
            self.local_proxy.state.connect(self.log_event)
            self.local_proxy.start()
            self.log_event(f"HTTP proxy listener starting on {host}:{port}")
        except Exception as exc:
            QMessageBox.warning(self, "Proxy listener", str(exc))

    def stop_proxy_listener(self):
        if self.local_proxy:
            try: self.local_proxy.stop()
            except Exception: pass
            self.local_proxy = None
            self.log_event("HTTP proxy listener stopped")

    def set_proxy_intercept(self, enabled: bool):
        if self.local_proxy:
            self.local_proxy.set_intercept(enabled)
        self.log_event(f"HTTP intercept {'enabled' if enabled else 'disabled'}")

    def on_proxy_message(self, msg: ProxyMessage):
        self.proxy_messages[msg.message_id] = msg
        if msg.state == "QUEUED" and self.local_proxy and self.local_proxy.intercept:
            row = self.proxy_intercept_table.rowCount(); self.proxy_intercept_table.insertRow(row)
            values = [msg.message_id, msg.method, msg.url, msg.state, msg.client, time.strftime("%H:%M:%S", time.localtime(msg.created_at))]
            for col, value in enumerate(values): self.proxy_intercept_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.proxy_intercept_table.item(row, 0).setData(Qt.UserRole, msg.message_id)
            self.log_event(f"Intercepted: {msg.method} {msg.url}")

    def on_proxy_response(self, msg: ProxyMessage):
        self.log_event(f"Proxy forwarded: {msg.method} {msg.url} → {msg.status} ({msg.response_size} bytes)")
        # Local HTTP listener traffic is also represented in the HTTP history.
        response_headers = {}; response_body = ""
        if msg.response_raw:
            head, sep, response_body = msg.response_raw.partition("\n\n")
            for line in head.splitlines()[1:]:
                if ":" in line:
                    k, v = line.split(":", 1); response_headers[k.strip()] = v.strip()
        rec = CapturedTransaction(request_id=f"proxy-{msg.message_id}", tab_id="local-proxy", resource_type="Document", method=msg.method, url=msg.url, request_headers=msg.headers, request_body=msg.body, status=msg.status, response_headers=response_headers, response_body=response_body, response_size=msg.response_size, timestamp=msg.created_at, duration_ms=msg.duration_ms)
        self.record_by_request[rec.request_id] = rec; self.records.append(rec); self.fill_traffic_row(rec); self.refresh_traffic_filters()

    def _selected_proxy_message(self) -> ProxyMessage | None:
        row = self.proxy_intercept_table.currentRow()
        if row < 0: return None
        item = self.proxy_intercept_table.item(row, 0)
        return self.proxy_messages.get(item.data(Qt.UserRole) if item else "")

    def release_selected_intercept(self):
        msg = self._selected_proxy_message()
        if msg and self.local_proxy:
            self.local_proxy.release(msg.message_id); self.log_event(f"Released intercept: {msg.message_id}")
            self._remove_intercept_row(msg.message_id)

    def drop_selected_intercept(self):
        msg = self._selected_proxy_message()
        if msg and self.local_proxy:
            self.local_proxy.drop(msg.message_id); self.log_event(f"Dropped intercept: {msg.message_id}")
            self._remove_intercept_row(msg.message_id)

    def _remove_intercept_row(self, message_id: str):
        for row in range(self.proxy_intercept_table.rowCount() - 1, -1, -1):
            item = self.proxy_intercept_table.item(row, 0)
            if item and item.data(Qt.UserRole) == message_id:
                self.proxy_intercept_table.removeRow(row); break

    def intercept_to_repeater(self):
        msg = self._selected_proxy_message()
        if not msg: return
        self.prepare_repeater(msg.method, msg.url, request_to_raw(msg.method, msg.url, msg.headers, msg.body))
        self.show_page("REPEATER"); self.log_event(f"Sent intercepted request to Repeater: {msg.method} {msg.url}")

    def intercept_to_intruder(self):
        msg = self._selected_proxy_message()
        if not msg: return
        self.intruder_request.setPlainText(request_to_raw(msg.method, msg.url, msg.headers, msg.body))
        self.show_page("INTRUDER"); self.log_event(f"Sent intercepted request to Intruder: {msg.method} {msg.url}")

    def clear_traffic_history(self):
        self.records.clear(); self.record_by_request.clear(); self.proxy_table.setRowCount(0); self.dashboard_table.setRowCount(0); self.log_event("HTTP history cleared")

    def refresh_traffic_filters(self, *_):
        query = self.proxy_filter.text().strip().lower() if hasattr(self, "proxy_filter") else ""
        only_scope = bool(self.proxy_scope_only.isChecked()) if hasattr(self, "proxy_scope_only") else False
        for table in [getattr(self, "proxy_table", None), getattr(self, "dashboard_table", None)]:
            if table is None: continue
            for row in range(table.rowCount()):
                vals = [table.item(row, c).text().lower() if table.item(row, c) else "" for c in range(table.columnCount())]
                rid = table.item(row, 1).data(Qt.UserRole) if table.item(row,1) else ""
                rec = self.record_by_request.get(rid)
                matches = not query or any(query in v for v in vals)
                scope_ok = True if not only_scope else bool(rec and is_in_scope(rec.url, self.scope_rules))
                table.setRowHidden(row, not (matches and scope_ok))

    def traffic_context_menu(self, table: QTableWidget, pos):
        item = table.itemAt(pos)
        if not item: return
        row = item.row(); url_item = table.item(row, 1); rec = self.record_by_request.get(url_item.data(Qt.UserRole)) if url_item else None
        if not rec: return
        menu = QMenu(self)
        menu.addAction("Send to Repeater", lambda: (self.prepare_repeater(rec.method, rec.url, self.request_text(rec)), self.show_page("REPEATER")))
        menu.addAction("Send to Intruder", lambda: (self.intruder_request.setPlainText(self.request_text(rec)), self.show_page("INTRUDER")))
        menu.addAction("Add host to scope", lambda: self._add_record_host_to_scope(rec))
        menu.addAction("Copy URL", lambda: QApplication.clipboard().setText(rec.url))
        menu.exec(QCursor.pos())

    def _add_record_host_to_scope(self, rec: CapturedTransaction):
        sp = urllib.parse.urlsplit(rec.url)
        if sp.netloc:
            self.scope_input.setText(f"{sp.scheme}://{sp.netloc}")
            self.add_scope()
            self.log_event(f"Added host to scope from history: {sp.netloc}")

    def show_proxy_selection(self):
        self.show_record_at_row(self.proxy_table.currentRow())

    def proxy_start_capture(self):
        try:
            self.start_capture(self.normalize_url(self.proxy_target.text()))
        except Exception as exc:
            QMessageBox.warning(self, "Proxy capture", str(exc))

    def proxy_send_to_repeater(self):
        rec = self.proxy_selected_record()
        if not rec:
            QMessageBox.information(self, "Proxy", "Select a captured request first.")
            return
        self.prepare_repeater(rec.method, rec.url, self.request_text(rec))
        self.show_page("REPEATER")
        self.log_event(f"Sent {rec.method} {rec.url} to Repeater")

    def proxy_selected_record(self):
        row = self.proxy_table.currentRow()
        if row < 0: return self.records[-1] if self.records else None
        item = self.proxy_table.item(row, 1)
        return self.record_by_request.get(item.data(Qt.UserRole)) if item else None

    @staticmethod
    def normalize_url(value: str) -> str:
        value = value.strip();
        if not value: raise ValueError("Target is empty")
        return value if re.match(r"^https?://", value, re.I) else "https://" + value

    # --------------------------------------------------------------- intruder
    def page_intruder(self) -> QWidget:
        w, l = self.page_frame("Intruder", "Controlled sequential parameter replay")
        source = self.card(1128, 154); sl = QGridLayout(source); sl.setContentsMargins(16, 14, 16, 14); sl.setHorizontalSpacing(10); sl.addWidget(label("Base request", 10, MUTED, True), 0, 0); self.intruder_parameter = QLineEdit(); self.intruder_parameter.setPlaceholderText("Parameter name, e.g. id"); sl.addWidget(self.intruder_parameter, 0, 1); load = QPushButton("Load selected traffic"); load.clicked.connect(self.load_selected_intruder); sl.addWidget(load, 0, 2); self.intruder_request = QPlainTextEdit(); self.intruder_request.setPlaceholderText("METHOD /path?param=value HTTP/1.1\nHost: target\n\nbody"); sl.addWidget(self.intruder_request, 1, 0, 1, 3); l.addWidget(source)
        body = QHBoxLayout(); payload_card = self.card(420, 520); pv = QVBoxLayout(payload_card); pv.setContentsMargins(16, 16, 16, 16); pv.addWidget(label("Payload set", 13, TEXT, True)); self.intruder_payloads = QPlainTextEdit(); self.intruder_payloads.setPlainText("'\n\"\n<kconk-test>\n{{7*7}}\n../"); pv.addWidget(self.intruder_payloads); controls = QHBoxLayout(); run = QPushButton("Start attack"); run.setObjectName("primary"); run.clicked.connect(self.start_intruder); stop = QPushButton("Stop"); stop.clicked.connect(self.stop_intruder); controls.addWidget(run); controls.addWidget(stop); pv.addLayout(controls); body.addWidget(payload_card)
        result = self.card(694, 520); rv = QVBoxLayout(result); rv.setContentsMargins(16, 16, 16, 16); rv.addWidget(label("Results", 13, TEXT, True)); self.intruder_table = QTableWidget(0, 6); self.intruder_table.setHorizontalHeaderLabels(["PAYLOAD","STATUS","LENGTH","TIME","URL","SNIPPET"]); self.intruder_table.setColumnWidth(0, 140); self.intruder_table.setColumnWidth(1, 70); self.intruder_table.setColumnWidth(2, 85); self.intruder_table.setColumnWidth(3, 75); self.intruder_table.setColumnWidth(4, 240); rv.addWidget(self.intruder_table); body.addWidget(result); l.addLayout(body); return w

    def load_selected_intruder(self):
        rec = self.selected_record()
        if not rec: return
        self.intruder_request.setPlainText(self.request_text(rec))
        params = urllib.parse.parse_qsl(urllib.parse.urlsplit(rec.url).query, keep_blank_values=True)
        if params and not self.intruder_parameter.text().strip():
            self.intruder_parameter.setText(params[0][0])
        self.log_event(f"Loaded request into Intruder: {rec.method} {rec.url}")

    def parse_request(self, text: str, fallback_url: str = "") -> tuple[str, str, dict[str, str], str]:
        method, url, headers, body, _version = parse_http_request_core(text, fallback_url)
        return method, url, headers, body

    def start_intruder(self):
        try: method, url, headers, body = self.parse_request(self.intruder_request.toPlainText())
        except Exception as exc: QMessageBox.warning(self, "Intruder", str(exc)); return
        parameter = self.intruder_parameter.text().strip()
        payloads = [x for x in self.intruder_payloads.toPlainText().splitlines() if x != ""]
        if not parameter or not payloads: QMessageBox.warning(self, "Intruder", "Enter a parameter and at least one payload."); return
        self.intruder_table.setRowCount(0); self.intruder_worker = IntruderWorker(method, url, headers, body, parameter, payloads); self.intruder_worker.row.connect(self.add_intruder_row); self.intruder_worker.failed.connect(lambda m: self.log_event(f"Intruder failed: {m}")); self.intruder_worker.done.connect(lambda: self.log_event("Intruder run complete")); self.intruder_worker.start(); self.log_event(f"Intruder started on {parameter} with {len(payloads[:50])} payloads")

    def stop_intruder(self):
        if self.intruder_worker: self.intruder_worker.stop_requested = True; self.log_event("Intruder stop requested")

    def add_intruder_row(self, data: dict):
        row = self.intruder_table.rowCount(); self.intruder_table.insertRow(row)
        values = [data["payload"], str(data["status"]), str(data["length"]), f"{data['time']} ms", data["url"], data["snippet"]]
        for i, v in enumerate(values): self.intruder_table.setItem(row, i, QTableWidgetItem(v))

    # --------------------------------------------------------------- repeater
    def page_repeater(self) -> QWidget:
        w, l = self.page_frame("Repeater", "Manual HTTP request editor and replay")
        toolbar = self.card(1128, 60); tl = QHBoxLayout(toolbar); tl.setContentsMargins(12, 10, 12, 10); self.rep_method = QComboBox(); self.rep_method.addItems(["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"]); self.rep_method.setFixedWidth(100); tl.addWidget(self.rep_method); self.rep_target = QLineEdit(); self.rep_target.setPlaceholderText("https://target.example/path"); tl.addWidget(self.rep_target); self.rep_protocol = QComboBox(); self.rep_protocol.addItems(["AUTO","HTTP/1.1","HTTP/2"]); self.rep_protocol.setFixedWidth(110); tl.addWidget(self.rep_protocol); send = QPushButton("Send"); send.setObjectName("primary"); send.clicked.connect(self.send_repeater); tl.addWidget(send); cancel = QPushButton("Cancel"); cancel.setObjectName("danger"); cancel.clicked.connect(self.cancel_repeater); tl.addWidget(cancel); save = QPushButton("Save"); save.clicked.connect(self.save_current_repeater); tl.addWidget(save); poc = QPushButton("CSRF PoC"); poc.clicked.connect(self.generate_csrf_poc); tl.addWidget(poc); add_spacer(tl); self.rep_status = label("—", 11, GOLD2, True); tl.addWidget(self.rep_status); l.addWidget(toolbar)
        split = QSplitter(Qt.Horizontal); split.setFixedHeight(700)
        left = self.card(560, 700); lv = QVBoxLayout(left); lv.setContentsMargins(12, 12, 12, 12); lv.addWidget(label("Request", 12, TEXT, True)); self.rep_request = QPlainTextEdit(); self.rep_request.setPlainText("GET / HTTP/1.1\nHost: example.com\n\n"); lv.addWidget(self.rep_request); split.addWidget(left)
        right = self.card(560, 700); rv = QVBoxLayout(right); rv.setContentsMargins(12, 12, 12, 12); rv.addWidget(label("Response", 12, TEXT, True)); self.rep_response = QPlainTextEdit(); self.rep_response.setReadOnly(True); rv.addWidget(self.rep_response); split.addWidget(right); split.setSizes([560,560]); l.addWidget(split); return w

    def prepare_repeater(self, method: str, url: str, request: str):
        self.rep_method.setCurrentText(method.upper()); self.rep_target.setText(url); self.rep_request.setPlainText(request)

    def send_repeater(self):
        if self.repeater_worker and self.repeater_worker.isRunning(): return
        try: method, url, headers, body = self.parse_request(self.rep_request.toPlainText(), self.rep_target.text().strip())
        except Exception as exc: self.rep_response.setPlainText("REQUEST ERROR\n\n" + str(exc)); return
        self.rep_method.setCurrentText(method); self.rep_target.setText(url); self.rep_status.setText("Sending…")
        self.repeater_worker = HttpReplayWorker(method, url, headers, body, self.rep_protocol.currentText()); self.repeater_worker.done.connect(self.repeater_done); self.repeater_worker.failed.connect(self.repeater_failed); self.repeater_worker.start(); self.log_event(f"Repeater sent: {method} {url}")

    def cancel_repeater(self):
        if self.repeater_worker and self.repeater_worker.isRunning(): self.repeater_worker.stop_requested = True; self.rep_status.setText("Cancelling…")

    def repeater_done(self, payload):
        raw, status, elapsed, size, final_url = payload; self.rep_response.setPlainText(raw); self.rep_status.setText(status); self.log_event(f"Repeater response: {status}, {size} bytes, {elapsed} ms")

    def repeater_failed(self, message): self.rep_response.setPlainText("REQUEST ERROR\n\n" + message); self.rep_status.setText("ERR"); self.log_event(f"Repeater error: {message}")

    def save_current_repeater(self):
        item = {"name": f"Request {len(self.saved_requests)+1}", "method": self.rep_method.currentText(), "url": self.rep_target.text().strip(), "request": self.rep_request.toPlainText(), "response": self.rep_response.toPlainText(), "notes": ""}; self.saved_requests.append(item); self.refresh_organizer(); self.log_event(f"Saved {item['name']}")

    # ------------------------------------------------------------ collaborator
    def page_collaborator(self) -> QWidget:
        w, l = self.page_frame("Collaborator", "Local canary generation for out-of-band correlation")
        c = self.card(1128, 250); cl = QVBoxLayout(c); cl.setContentsMargins(18, 18, 18, 18); cl.addWidget(label("Canary token", 13, TEXT, True)); row = QHBoxLayout(); self.canary = QLineEdit(); self.canary.setReadOnly(True); row.addWidget(self.canary); gen = QPushButton("Generate"); gen.setObjectName("primary"); gen.clicked.connect(self.generate_canary); row.addWidget(gen); cl.addLayout(row); cl.addWidget(label("Use the generated token as a unique marker in an authorized test. This local module does not provide a remote Collaborator server.", 11, TEXT2)); l.addWidget(c)
        log = self.card(1128, 400); lv = QVBoxLayout(log); lv.addWidget(label("Correlation notes", 13, TEXT, True)); self.collab_notes = QPlainTextEdit(); self.collab_notes.setPlaceholderText("Record where the canary was placed and what callback evidence you observed externally."); lv.addWidget(self.collab_notes); l.addWidget(log); return w

    def generate_canary(self):
        token = f"kconk-{int(time.time())}-{base64.urlsafe_b64encode(Path('/dev/urandom').read_bytes(6)).decode().rstrip('=')}"; self.canary.setText(token); self.log_event("Generated Collaborator canary")

    # ---------------------------------------------------------------- sequencer
    def page_sequencer(self) -> QWidget:
        w, l = self.page_frame("Sequencer", "Offline token randomness inspection")
        left = self.card(548, 650); lv = QVBoxLayout(left); lv.addWidget(label("Samples", 13, TEXT, True)); self.seq_samples = QPlainTextEdit(); self.seq_samples.setPlaceholderText("Paste one token per line"); lv.addWidget(self.seq_samples); run = QPushButton("Analyze randomness"); run.setObjectName("primary"); run.clicked.connect(self.analyze_sequence); lv.addWidget(run);
        right = self.card(560, 650); rv = QVBoxLayout(right); rv.addWidget(label("Result", 13, TEXT, True)); self.seq_result = QPlainTextEdit(); self.seq_result.setReadOnly(True); rv.addWidget(self.seq_result); box = QWidget(); grid = QGridLayout(box); grid.addWidget(label("Samples",10,MUTED,True),0,0); self.seq_count=label("0",18,GOLD2,True); grid.addWidget(self.seq_count,0,1); grid.addWidget(label("Entropy",10,MUTED,True),1,0); self.seq_entropy=label("0.000",18,GOLD2,True); grid.addWidget(self.seq_entropy,1,1); rv.addWidget(box); row=QHBoxLayout(); row.addWidget(left); row.addWidget(right); l.addLayout(row); return w

    def analyze_sequence(self):
        samples = [x.strip() for x in self.seq_samples.toPlainText().splitlines() if x.strip()]
        joined = "".join(samples); counts = {c: joined.count(c) for c in set(joined)}; total = len(joined); entropy = -sum((n/total) * math.log2(n/total) for n in counts.values()) if total else 0.0
        self.seq_count.setText(str(len(samples))); self.seq_entropy.setText(f"{entropy:.3f}"); self.seq_result.setPlainText(json.dumps({"samples":len(samples),"total_characters":total,"unique_characters":len(counts),"entropy_bits_per_character":round(entropy,6),"min_length":min((len(x) for x in samples),default=0),"max_length":max((len(x) for x in samples),default=0)}, indent=2)); self.log_event("Sequencer sample analysis complete")

    # ---------------------------------------------------------------- decoder
    def page_decoder(self) -> QWidget:
        w, l = self.page_frame("Decoder", "Encode / decode helpers for request analysis")
        c = self.card(1128, 690); cv = QVBoxLayout(c); row=QHBoxLayout(); self.dec_mode=QComboBox(); self.dec_mode.addItems(["Base64","URL","Hex","HTML","JWT","SHA256","SHA1","MD5","SHA512"]); row.addWidget(self.dec_mode,0); enc=QPushButton("Encode"); enc.clicked.connect(self.decode_run_encode); row.addWidget(enc); dec=QPushButton("Decode"); dec.setObjectName("primary"); dec.clicked.connect(self.decode_run_decode); row.addWidget(dec); add_spacer(row); cv.addLayout(row); io=QSplitter(Qt.Horizontal); self.dec_in=QPlainTextEdit(); self.dec_out=QPlainTextEdit(); self.dec_out.setReadOnly(False); io.addWidget(self.dec_in); io.addWidget(self.dec_out); cv.addWidget(io); l.addWidget(c); return w

    def decode_run_encode(self): self.decode_transform(True)
    def decode_run_decode(self): self.decode_transform(False)
    def decode_transform(self, encode: bool):
        data=self.dec_in.toPlainText(); mode=self.dec_mode.currentText();
        try:
            if mode=="Base64": out=base64.b64encode(data.encode()).decode() if encode else base64.b64decode(data + "="*((4-len(data)%4)%4)).decode(errors="replace")
            elif mode=="URL": out=urllib.parse.quote(data,safe="") if encode else urllib.parse.unquote(data)
            elif mode=="Hex": out=data.encode().hex() if encode else bytes.fromhex(data.strip()).decode(errors="replace")
            elif mode=="HTML": out=html.escape(data) if encode else html.unescape(data)
            elif mode in {"SHA256","SHA1","MD5","SHA512"}:
                if not encode: out=hash_text(data, mode)
                else: raise ValueError("Hash functions are one-way; use Decode to calculate a digest")
            else: out=self.jwt_transform(data, encode)
            self.dec_out.setPlainText(out); self.log_event(f"Decoder {mode} {'encode' if encode else 'decode'}")
        except Exception as exc: self.dec_out.setPlainText("ERROR: "+str(exc))

    @staticmethod
    def jwt_transform(data: str, encode: bool) -> str:
        if encode:
            obj = json.loads(data)
            header = obj.get("header") if isinstance(obj, dict) else None
            payload = obj.get("payload") if isinstance(obj, dict) else None
            signature = obj.get("signature", "") if isinstance(obj, dict) else ""
            if not isinstance(header, dict) or not isinstance(payload, dict):
                raise ValueError("Encode expects JSON with object fields: header, payload, signature")
            def enc(part):
                raw = json.dumps(part, separators=(",", ":"), ensure_ascii=False).encode()
                return base64.urlsafe_b64encode(raw).decode().rstrip("=")
            return f"{enc(header)}.{enc(payload)}.{signature}"
        obj = decode_jwt(data)
        return json.dumps(obj, indent=2, ensure_ascii=False)

    # ---------------------------------------------------------------- comparer
    def page_comparer(self) -> QWidget:
        w,l=self.page_frame("Comparer","Diff two requests, responses or arbitrary text")
        c=self.card(1128,690); cv=QVBoxLayout(c); bar=QHBoxLayout(); run=QPushButton("Compare"); run.setObjectName("primary"); run.clicked.connect(self.compare_text); bar.addWidget(run); swap=QPushButton("Swap"); swap.clicked.connect(lambda: self.swap_compare()); bar.addWidget(swap); add_spacer(bar); cv.addLayout(bar); split=QSplitter(Qt.Horizontal); self.comp_a=QPlainTextEdit(); self.comp_b=QPlainTextEdit(); self.comp_result=QPlainTextEdit(); self.comp_result.setReadOnly(True); split.addWidget(self.comp_a); split.addWidget(self.comp_b); split.addWidget(self.comp_result); split.setSizes([370,370,370]); cv.addWidget(split); l.addWidget(c); return w

    def compare_text(self):
        a=self.comp_a.toPlainText().splitlines(); b=self.comp_b.toPlainText().splitlines(); diff="\n".join(difflib.unified_diff(a,b,fromfile="A",tofile="B",lineterm="")); self.comp_result.setPlainText(diff or "No differences"); self.log_event("Comparer run")
    def swap_compare(self): a=self.comp_a.toPlainText(); self.comp_a.setPlainText(self.comp_b.toPlainText()); self.comp_b.setPlainText(a)

    # ---------------------------------------------------------------- logger
    def page_logger(self) -> QWidget:
        w,l=self.page_frame("Logger","Unified KCONK event history")
        c=self.card(1128,690); cv=QVBoxLayout(c); bar=QHBoxLayout(); clear=QPushButton("Clear"); clear.clicked.connect(self.clear_logger); bar.addWidget(clear); export=QPushButton("Export text"); export.clicked.connect(self.export_log); bar.addWidget(export); add_spacer(bar); cv.addLayout(bar); self.logger_table=QTableWidget(0,2); self.logger_table.setHorizontalHeaderLabels(["TIME","EVENT"]); self.logger_table.setColumnWidth(0,90); self.logger_table.setColumnWidth(1,930); cv.addWidget(self.logger_table); l.addWidget(c); return w

    def clear_logger(self): self.events.clear(); self.logger_table.setRowCount(0); self.log_event("Logger cleared")
    def export_log(self): self.comp_a.setPlainText("\n".join(self.events)); self.show_page("COMPARER"); self.log_event("Copied logger into Comparer")

    # -------------------------------------------------------------- organizer
    def page_organizer(self) -> QWidget:
        w, l = self.page_frame("Organizer", "Save and reuse request templates")
        c = self.card(1128, 690)
        cv = QVBoxLayout(c)
        bar = QHBoxLayout()
        save = QPushButton("Save current Repeater")
        save.setObjectName("primary")
        save.clicked.connect(self.save_current_repeater)
        bar.addWidget(save)
        load = QPushButton("Load selected")
        load.clicked.connect(self.load_selected_organizer)
        bar.addWidget(load)
        add_spacer(bar)
        cv.addLayout(bar)
        split = QSplitter(Qt.Horizontal)
        self.organizer_list = QListWidget()
        self.organizer_list.itemClicked.connect(self.show_organizer_item)
        self.organizer_list.itemDoubleClicked.connect(self.load_saved_request)
        split.addWidget(self.organizer_list)
        self.organizer_notes = QPlainTextEdit()
        self.organizer_notes.setPlaceholderText("Notes for the selected request")
        split.addWidget(self.organizer_notes)
        split.setSizes([470, 620])
        cv.addWidget(split)
        l.addWidget(c)
        self.refresh_organizer()
        return w

    def refresh_organizer(self):
        if not hasattr(self,"organizer_list"): return
        self.organizer_list.clear()
        for item in self.saved_requests: self.organizer_list.addItem(f"{item['name']}  •  {item['method']}  •  {item['url']}")

    def load_saved_request(self, item: QListWidgetItem):
        idx=self.organizer_list.row(item)
        if idx<0 or idx>=len(self.saved_requests): return
        r=self.saved_requests[idx]; self.prepare_repeater(r["method"],r["url"],r["request"]); self.show_page("REPEATER"); self.log_event(f"Loaded {r['name']}")

    def show_organizer_item(self, item: QListWidgetItem):
        idx = self.organizer_list.row(item)
        if 0 <= idx < len(self.saved_requests):
            self.organizer_notes.setPlainText(self.saved_requests[idx].get("notes", ""))

    def load_selected_organizer(self):
        item = self.organizer_list.currentItem()
        if item: self.load_saved_request(item)

    # ------------------------------------------------------------- extensions
    def page_extensions(self) -> QWidget:
        w,l=self.page_frame("Extensions","Local Python extension registry")
        c=self.card(1128,690); cv=QVBoxLayout(c); row=QHBoxLayout(); reloadb=QPushButton("Refresh"); reloadb.clicked.connect(self.refresh_extensions); row.addWidget(reloadb); load=QPushButton("Load selected"); load.setObjectName("primary"); load.clicked.connect(self.load_selected_extension); row.addWidget(load); add_spacer(row); cv.addLayout(row); self.ext_list=QListWidget(); cv.addWidget(self.ext_list); self.ext_detail=QPlainTextEdit(); self.ext_detail.setReadOnly(True); cv.addWidget(self.ext_detail); l.addWidget(c); QTimer.singleShot(0,self.refresh_extensions); return w

    def refresh_extensions(self):
        if not hasattr(self,"ext_list"): return
        self.ext_list.clear()
        for path in sorted(EXTENSIONS.glob("*.py")):
            if path.name.startswith("__"): continue
            self.ext_list.addItem(path.name)
        self.ext_detail.setPlainText("Extensions expose register(app). The example extension only records a log event.")

    def load_selected_extension(self):
        item=self.ext_list.currentItem();
        if not item: return
        path=EXTENSIONS/item.text(); spec=importlib.util.spec_from_file_location(path.stem,path); mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)
        register=getattr(mod,"register",None)
        if not callable(register): raise RuntimeError("Extension has no register(app) function")
        register(self); self.log_event(f"Extension loaded: {path.name}")

    # ---------------------------------------------------------------- discover
    def page_discover(self) -> QWidget:
        w,l=self.page_frame("Discover","CTF-oriented passive + controlled web analysis")
        c=self.card(1128,690); cv=QVBoxLayout(c); nav=QHBoxLayout(); self.discover_mode=QComboBox(); self.discover_mode.addItems(["Overview","Site map","Forms","Technologies","Secrets","JWT","Findings","Payload catalog"]); nav.addWidget(self.discover_mode); show=QPushButton("Refresh from latest analysis"); show.setObjectName("primary"); show.clicked.connect(self.refresh_discover); nav.addWidget(show); add_spacer(nav); cv.addLayout(nav); self.discover_output=QPlainTextEdit(); self.discover_output.setReadOnly(True); cv.addWidget(self.discover_output); self.discover_mode.currentTextChanged.connect(self.refresh_discover); l.addWidget(c); return w

    def refresh_discover(self):
        r=self.current_result
        mode=self.discover_mode.currentText()
        if not r:
            if mode=="Payload catalog": self.discover_output.setPlainText(json.dumps({k:v["payloads"] for k,v in PAYLOAD_CATALOG.items()},indent=2))
            else: self.discover_output.setPlainText("No analysis result yet. Run Target → Analyze target.")
            return
        findings = []
        for item in r.payload_runs:
            findings.append({"state": item.state, "family": item.family, "parameter": item.parameter, "payload": item.payload, "status": item.status, "diff": item.diff_summary, "evidence": item.evidence, "source_urls": item.source_urls})
        data={"Overview":{"target":r.target,"requests":len(r.requests),"site_map":len(r.site_map),"forms":len(r.forms),"js_files":len(r.js_files),"technologies":r.technologies,"secrets":r.secrets,"jwt":len(r.jwt_tokens),"findings":len(r.payload_runs)},"Site map":r.site_map,"Forms":r.forms,"Technologies":r.technologies,"Secrets":r.secrets,"JWT":[asdict(x) for x in r.jwt_tokens],"Findings":findings,"Payload catalog":{k:v["payloads"] for k,v in PAYLOAD_CATALOG.items()}}.get(mode)
        self.discover_output.setPlainText(json.dumps(data,indent=2,ensure_ascii=False))

    # -------------------------------------------------------------- project I/O
    def project_menu(self):
        menu = QMenu(self)
        menu.addAction("Save project…", self.save_project_dialog)
        menu.addAction("Load project…", self.load_project_dialog)
        menu.addSeparator()
        menu.addAction("Extensions", lambda: self.show_page("EXTENSIONS"))
        menu.exec(QCursor.pos())

    def save_project_dialog(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save KCONK project", "kconk_project.json", "KCONK Project (*.json)")
        if not path: return
        data = []
        for rec in self.records:
            data.append(asdict(rec))
        export_project(path, scopes=[r.pattern for r in self.scope_rules], saved_requests=self.saved_requests, events=self.events, records=data)
        self.log_event(f"Project saved: {path}")

    def load_project_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load KCONK project", "", "KCONK Project (*.json)")
        if not path: return
        try:
            payload = import_project(path)
            self.scope_rules = [ScopeRule(x, True) for x in payload.get("scopes", [])]
            self.saved_requests = list(payload.get("saved_requests", []))
            self.events = list(payload.get("events", []))
            self.records.clear(); self.record_by_request.clear(); self.proxy_table.setRowCount(0); self.dashboard_table.setRowCount(0)
            for data in payload.get("records", []):
                rec = CapturedTransaction(**{k: data.get(k) for k in CapturedTransaction.__dataclass_fields__.keys()})
                self.records.append(rec); self.record_by_request[rec.request_id] = rec; self.fill_traffic_row(rec)
            self.refresh_organizer(); self.refresh_traffic_filters()
            if hasattr(self, "logger_table"):
                self.logger_table.setRowCount(0)
                for line in reversed(self.events):
                    parts = line.split("] ", 1); stamp = parts[0].lstrip("[") if len(parts) == 2 else ""; event = parts[1] if len(parts) == 2 else line
                    row = self.logger_table.rowCount(); self.logger_table.insertRow(row); self.logger_table.setItem(row, 0, QTableWidgetItem(stamp)); self.logger_table.setItem(row, 1, QTableWidgetItem(event))
            self.log_event(f"Project loaded: {path}")
        except Exception as exc:
            QMessageBox.warning(self, "Project", str(exc))

    def generate_csrf_poc(self):
        try:
            method, url, headers, body = self.parse_request(self.rep_request.toPlainText(), self.rep_target.text().strip())
        except Exception as exc:
            QMessageBox.warning(self, "CSRF PoC", str(exc)); return
        sp = urllib.parse.urlsplit(url); fields = urllib.parse.parse_qsl(body, keep_blank_values=True) if body else []
        lines = ["<!doctype html>", "<html><body>", f'<form action="{html.escape(url, quote=True)}" method="{method}">']
        if fields:
            for key, value in fields:
                lines.append(f'<input type="hidden" name="{html.escape(key, quote=True)}" value="{html.escape(value, quote=True)}">')
        lines += ['<input type="submit" value="Submit">', "</form>", "</body></html>"]
        self.dec_mode.setCurrentText("HTML") if hasattr(self, "dec_mode") else None
        self.show_page("DECODER")
        self.dec_in.setPlainText("\n".join(lines))
        self.log_event(f"Generated CSRF PoC for {method} {sp.netloc}{sp.path}")

    # ---------------------------------------------------------------- misc
    def closeEvent(self, event):
        self.stop_capture(False)
        self.stop_proxy_listener()
        for worker in (self.analysis_worker,self.repeater_worker,self.intruder_worker):
            if worker and worker.isRunning():
                try: worker.terminate(); worker.wait(500)
                except Exception: pass
        super().closeEvent(event)
