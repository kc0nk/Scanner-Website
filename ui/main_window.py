from __future__ import annotations
import html
from datetime import datetime
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit
import httpx
from PySide6.QtCore import Qt, QThread, Signal, QUrl
from PySide6.QtGui import QFont, QColor, QBrush, QPen
from PySide6.QtWidgets import *
from app.version import __version__
from core.analyzer import WebAnalyzer, AnalysisResult
from core.chrome_capture import ChromeCaptureThread, CapturedTransaction, launch_chrome, find_free_port

BG="#050b1a"; PANEL="#0b1428"; BORDER="#1a2a48"; TEXT="#d8e3f3"; MUTED="#7f91aa"; CYAN="#11c8ef"; PURPLE="#9b5cff"; RED="#ff4f78"; GREEN="#21d7a5"; GOLD="#f5b82e"
STYLE=f'''
*{{font-family:"DejaVu Sans"; color:{TEXT};}}
QMainWindow,QWidget{{background:{BG};}}
QLabel{{background:transparent;}}
QFrame#sidebar{{background:#070e1d; border-right:1px solid {BORDER};}}
QFrame#topbar{{background:#080f20; border-bottom:1px solid {BORDER};}}
QFrame#card,QFrame#panel{{background:{PANEL}; border:1px solid {BORDER}; border-radius:14px;}}
QFrame#analyzerHeader{{background:#091326; border:1px solid {BORDER}; border-radius:14px;}}
QFrame#analyzerStatus{{background:#071a18; border:1px solid #0e4f47; border-radius:8px;}}
QFrame#analyzerContent{{background:transparent; border:0;}}
QFrame#repPane{{background:{PANEL}; border:1px solid {BORDER}; border-radius:10px;}}
QFrame#repPaneHeader{{background:#0b1628; border:0; border-bottom:1px solid {BORDER};}}
QFrame#repToolbar{{background:#080f20; border:1px solid {BORDER}; border-radius:9px;}}
QFrame#repFooter{{background:#080f20; border:0; border-top:1px solid {BORDER};}}
QFrame#repTargetBox{{background:#071225; border:1px solid #142846; border-radius:7px; min-height:36px;}}
QFrame#repTabBar{{background:transparent; border:0;}}
QFrame#repPane{{min-width:0; min-height:0;}}
QTabWidget#repTabs{{background:transparent; border:0; padding:0; margin:0;}}
QTabWidget#repTabs::pane{{border:0; background:transparent; top:0;}}
QTabWidget#repTabs QTabBar{{background:transparent; qproperty-drawBase:0; left:0;}}
QTabWidget#repTabs QTabBar::tab{{background:#081224; border:1px solid #1b3154; padding:0 14px; min-width:58px; max-width:110px; min-height:34px; max-height:34px; margin:2px 4px 2px 0; border-radius:8px; color:{MUTED};}}
QTabWidget#repTabs QTabBar::tab:hover{{background:#0d1b31; color:{TEXT}; border-color:#29466f;}}
QTabWidget#repTabs QTabBar::tab:selected{{background:#103455; color:{CYAN}; border-color:#1689b0;}}
QTabWidget#repRequestViews,QTabWidget#repResponseViews{{border:0; background:transparent; padding:0; margin:0;}}
QTabWidget#repRequestViews::pane,QTabWidget#repResponseViews::pane{{border:0; background:#050d1a; top:0;}}
QTabWidget#repRequestViews QTabBar,QTabWidget#repResponseViews QTabBar{{background:#091225; qproperty-drawBase:0; left:8px;}}
QTabWidget#repRequestViews QTabBar::tab,QTabWidget#repResponseViews QTabBar::tab{{background:transparent; border:0; border-bottom:2px solid transparent; border-radius:0; padding:0 12px; min-height:34px; max-height:34px; margin:0 2px; color:{MUTED};}}
QTabWidget#repRequestViews QTabBar::tab:hover,QTabWidget#repResponseViews QTabBar::tab:hover{{background:#0c1930; color:{TEXT};}}
QTabWidget#repRequestViews QTabBar::tab:selected,QTabWidget#repResponseViews QTabBar::tab:selected{{background:#0c1930; color:{CYAN}; border-bottom-color:{CYAN};}}
QPushButton#repPlus{{background:#0c1b31; border:1px solid #233b60; border-radius:8px; color:{TEXT}; font-size:18px; padding:0;}}
QPushButton#repPlus:hover{{background:#102844; border-color:{CYAN}; color:white;}}

QLineEdit,QPlainTextEdit,QTextBrowser,QTableWidget,QListWidget,QComboBox{{background:#071023; border:1px solid {BORDER}; border-radius:10px; padding:8px; selection-background-color:#123e64;}}
QPushButton{{background:#111d35; border:1px solid #26395c; border-radius:9px; padding:9px 14px; font-weight:600;}}
QPushButton:hover{{border-color:{CYAN}; background:#10263d;}}
QPushButton#primary{{background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #1768f5, stop:1 #13bde8); color:white; border:0;}}
QPushButton.nav{{text-align:left; border:0; background:transparent; color:#91a0b7; padding:12px 14px;}}
QPushButton.nav:hover{{background:#0e1c32; color:white;}}
QPushButton.nav[active="true"]{{background:#102f55; color:{CYAN}; border:1px solid #12516c;}}
QListWidget#analyzerNav{{background:#071021; border:0; padding:4px;}}
QListWidget#analyzerNav::item{{background:transparent; border:1px solid transparent; border-radius:8px; padding:10px 8px; color:#91a0b7;}}
QListWidget#analyzerNav::item:hover{{background:#0d1b31; color:{TEXT};}}
QListWidget#analyzerNav::item:selected{{background:#0f3153; border:1px solid #12516c; color:{CYAN}; font-weight:700;}}
QListWidget#findingList{{background:transparent; border:0; padding:2px;}}
QListWidget#findingList::item{{background:#081426; border:1px solid #193050; border-radius:10px; padding:13px; margin:2px 0;}}
QListWidget#findingList::item:selected{{background:#10233d; border-color:#24608f;}}
QHeaderView::section{{background:#0d182b; color:#8da0ba; border:0; border-bottom:1px solid {BORDER}; padding:10px;}}
QTableWidget{{gridline-color:#10203a;}}
QTabBar::tab{{background:#0b162b; border:1px solid {BORDER}; padding:10px 16px; margin-right:5px; border-radius:9px; color:#91a0b7;}}
QTabBar::tab:selected{{background:#103657; color:{CYAN}; border-color:#176383;}}
QScrollArea{{border:0;}}
'''

class Worker(QThread):
    done=Signal(object); failed=Signal(str); line=Signal(str)
    def __init__(self,target,records):
        super().__init__(); self.target=target; self.records=list(records or [])
    def run(self):
        try:self.done.emit(WebAnalyzer().run_from_history(self.records,self.target,self.line.emit))
        except Exception as e:self.failed.emit(str(e))

class Metric(QFrame):
    def __init__(self,title,value,accent=CYAN):
        super().__init__(); self.setObjectName("card"); l=QVBoxLayout(self); l.setContentsMargins(20,16,20,16)
        a=QLabel(title.upper()); a.setStyleSheet(f"color:{MUTED};font-size:11px;letter-spacing:2px;")
        self.value=QLabel(str(value)); self.value.setStyleSheet(f"color:{accent};font-size:27px;font-weight:700;")
        l.addWidget(a);l.addWidget(self.value)
    def setValue(self,v):self.value.setText(str(v))

class RepeaterWorker(QThread):
    done=Signal(object)
    failed=Signal(str)
    cancelled=Signal()

    def __init__(self, method, url, headers, body):
        super().__init__()
        self.method=method.upper()
        self.url=url
        self.headers=headers
        self.body=body
        self.stop_requested=False

    def run(self):
        import time
        started=time.perf_counter()
        try:
            timeout=httpx.Timeout(connect=5.0, read=1.0, write=5.0, pool=5.0)
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
                with client.stream(
                    self.method,
                    self.url,
                    headers=self.headers,
                    content=self.body.encode("utf-8") if self.body else None,
                ) as response:
                    chunks=[]
                    for chunk in response.iter_bytes():
                        if self.stop_requested:
                            self.cancelled.emit()
                            return
                        chunks.append(chunk)
                    if self.stop_requested:
                        self.cancelled.emit()
                        return
                    content=b"".join(chunks)
                    elapsed=int((time.perf_counter()-started)*1000)
                    status=f"{response.status_code} {response.reason_phrase}"
                    header_text="\n".join(f"{k}: {v}" for k,v in response.headers.items())
                    body_text=content.decode("utf-8", errors="replace")
                    raw=f"{response.http_version} {response.status_code} {response.reason_phrase}\n{header_text}\n\n{body_text}"
                    self.done.emit((raw,status,elapsed,len(content),str(response.url)))
        except Exception as e:
            if self.stop_requested:
                self.cancelled.emit()
            else:
                self.failed.emit(str(e))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle(f"CTF Exploit Workbench v{__version__}"); self.resize(1500,900); self.setStyleSheet(STYLE); self.result=None; self.worker=None; self.chrome_capture=None; self.chrome_process=None; self.chrome_profile=None; self.browser_records=[]; self.browser_row_map={}
        root=QWidget(); self.setCentralWidget(root); outer=QHBoxLayout(root); outer.setContentsMargins(0,0,0,0); outer.setSpacing(0); outer.addWidget(self.sidebar())
        body=QVBoxLayout(); body.setContentsMargins(0,0,0,0); body.setSpacing(0); body.addWidget(self.topbar()); self.stack=QStackedWidget(); body.addWidget(self.stack); outer.addLayout(body,1)
        self.pages={}
        for name,fn in [("Dashboard",self.dashboard),("Web Analyzer",self.analyzer),("Workflow",self.workflow),("Repeater",self.repeater)]:
            w=fn(); self.pages[name]=w; self.stack.addWidget(w)
        self.show_page("Dashboard")

    def sidebar(self):
        f=QFrame();f.setObjectName("sidebar");f.setFixedWidth(300);l=QVBoxLayout(f);l.setContentsMargins(20,22,20,20)
        brand=QHBoxLayout();icon=QLabel("◈");icon.setStyleSheet(f"font-size:30px;color:{CYAN};");brand.addWidget(icon);b=QVBoxLayout();n=QLabel("CTF EXPLOIT WORKBENCH");n.setStyleSheet("font-weight:800;font-size:15px;");s=QLabel("DESKTOP WEB ANALYSIS");s.setStyleSheet(f"color:{MUTED};font-size:10px;letter-spacing:2px;");b.addWidget(n);b.addWidget(s);brand.addLayout(b);l.addLayout(brand);l.addSpacing(30)
        self.nav={}
        for text in ["Dashboard","Web Analyzer","Workflow","Repeater"]:
            btn=QPushButton("  ◉   "+text);btn.setObjectName("nav");btn.setProperty("active",False);btn.clicked.connect(lambda _,x=text:self.show_page(x));self.nav[text]=btn;l.addWidget(btn)
        l.addStretch();card=QFrame();card.setObjectName("card");cl=QVBoxLayout(card);row=QHBoxLayout();av=QLabel("H");av.setFixedSize(42,42);av.setAlignment(Qt.AlignCenter);av.setStyleSheet("background:#0ea5e9;border-radius:12px;color:white;font-size:18px;font-weight:800;");row.addWidget(av);info=QVBoxLayout();info.addWidget(QLabel("hackers01"));em=QLabel("desktop.local");em.setStyleSheet(f"color:{MUTED};font-size:11px;");info.addWidget(em);row.addLayout(info);cl.addLayout(row);l.addWidget(card);return f

    def topbar(self):
        f=QFrame();f.setObjectName("topbar");f.setFixedHeight(76);l=QHBoxLayout(f);l.setContentsMargins(28,12,28,12);l.addStretch()
        l.addWidget(QPushButton("H   hackers01  ▾"));return f

    def page(self):
        s=QScrollArea();s.setWidgetResizable(True);w=QWidget();l=QVBoxLayout(w);l.setContentsMargins(40,38,40,40);l.setSpacing(22);s.setWidget(w);return s,l
    def title(self,l,ey,heading,sub=""):
        e=QLabel(ey.upper());e.setStyleSheet(f"color:{MUTED};font-size:11px;letter-spacing:2px;");l.addWidget(e);h=QLabel(heading);h.setStyleSheet("font-size:30px;font-weight:800;");l.addWidget(h)
        if sub:q=QLabel(sub);q.setStyleSheet(f"color:{MUTED};font-size:13px;");l.addWidget(q)

    def dashboard(self):
        s,l=self.page()
        # Compact reference-style dashboard.
        hero=QFrame(); hero.setObjectName("panel")
        hl=QHBoxLayout(hero); hl.setContentsMargins(24,16,24,16); hl.setSpacing(18)
        left=QVBoxLayout(); left.setSpacing(6)
        tag=QLabel("●  SYSTEM ACTIVE")
        tag.setStyleSheet(f"color:{GREEN};background:#062c2a;border:1px solid #0d6157;border-radius:15px;padding:5px 10px;")
        tag.setFixedWidth(150); left.addWidget(tag)
        hi=QLabel("Hello, <font color='#3b9bff'>hackers01</font> 👋")
        hi.setStyleSheet("font-size:25px;font-weight:800;"); left.addWidget(hi)
        hl.addLayout(left); hl.addStretch()
        l.addWidget(hero)

        url_card=QFrame(); url_card.setObjectName("card")
        ul=QVBoxLayout(url_card); ul.setContentsMargins(18,14,18,14); ul.setSpacing(8)
        label=QLabel("PROJECT URL")
        label.setStyleSheet(f"color:{MUTED};font-size:10px;font-weight:700;letter-spacing:2px;"); ul.addWidget(label)
        row=QHBoxLayout(); row.setSpacing(10)
        self.dashboard_url=QLineEdit(); self.dashboard_url.setPlaceholderText("https://target.example")
        self.dashboard_url.returnPressed.connect(self.open_dashboard_target); row.addWidget(self.dashboard_url,1)
        open_url=QPushButton("Open"); open_url.setObjectName("primary"); open_url.clicked.connect(self.open_dashboard_target); row.addWidget(open_url)
        ul.addLayout(row); l.addWidget(url_card)

        history_card=QFrame(); history_card.setObjectName("card")
        hv=QVBoxLayout(history_card); hv.setContentsMargins(14,12,14,14); hv.setSpacing(8)
        hrow=QHBoxLayout(); title=QLabel("HTTP HISTORY"); title.setStyleSheet("font-size:15px;font-weight:800;"); hrow.addWidget(title)
        self.history_count=QLabel("0 requests"); self.history_count.setStyleSheet(f"color:{MUTED};font-size:11px;"); hrow.addStretch(); hrow.addWidget(self.history_count); hv.addLayout(hrow)
        self.history_table=QTableWidget(0,9)
        self.history_table.setHorizontalHeaderLabels(["METHOD","URL","PARAMS","STATUS","LENGTH","MIME TYPE","EDITED","COOKIES","TIME"])
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectRows); self.history_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.history_table.setAlternatingRowColors(False); self.history_table.setSortingEnabled(False)
        hh=self.history_table.horizontalHeader(); hh.setSectionResizeMode(0,QHeaderView.ResizeToContents); hh.setSectionResizeMode(1,QHeaderView.Stretch)
        for i in [2,3,4,5,6,7,8]: hh.setSectionResizeMode(i,QHeaderView.Interactive)
        self.history_table.setColumnWidth(2,80); self.history_table.setColumnWidth(3,70); self.history_table.setColumnWidth(4,85); self.history_table.setColumnWidth(5,110); self.history_table.setColumnWidth(6,70); self.history_table.setColumnWidth(7,90); self.history_table.setColumnWidth(8,120)
        self.history_table.setMinimumHeight(240); self.history_table.itemSelectionChanged.connect(self.history_selected)
        self.history_table.cellDoubleClicked.connect(self.history_to_repeater)
        self.history_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self._history_context_menu)

        hint=QLabel("Drag the divider between HTTP History and Request/Response to resize the history area. Drag column borders to resize columns.")
        hint.setStyleSheet(f"color:{MUTED};font-size:10px;"); hv.addWidget(hint)

        # Vertical splitter: the HTTP History table can be expanded/shrunk like Burp's history pane.
        history_splitter=QSplitter(Qt.Vertical)
        history_splitter.setChildrenCollapsible(False)
        history_splitter.setHandleWidth(8)
        history_splitter.setMinimumHeight(520)
        history_splitter.addWidget(self.history_table)

        details=QSplitter(Qt.Horizontal); details.setChildrenCollapsible(False); details.setMinimumHeight(220)
        req=QFrame(); req.setObjectName("panel"); rv=QVBoxLayout(req); rv.setContentsMargins(12,10,12,10); rv.addWidget(QLabel("REQUEST")); self.dashboard_request=QPlainTextEdit(); self.dashboard_request.setReadOnly(True); rv.addWidget(self.dashboard_request)
        resp=QFrame(); resp.setObjectName("panel"); sv=QVBoxLayout(resp); sv.setContentsMargins(12,10,12,10); sv.addWidget(QLabel("RESPONSE")); self.dashboard_response=QPlainTextEdit(); self.dashboard_response.setReadOnly(True); sv.addWidget(self.dashboard_response)
        details.addWidget(req); details.addWidget(resp); details.setSizes([500,500])
        history_splitter.addWidget(details)
        history_splitter.setSizes([560,220])
        hv.addWidget(history_splitter,1)
        l.addWidget(history_card,1)
        return s

    def open_dashboard_target(self):
        url=self.dashboard_url.text().strip()
        if not url:
            return
        if not url.lower().startswith(("http://", "https://")):
            url = "https://" + url
            self.dashboard_url.setText(url)
        try:
            self._start_chrome_capture(url)
        except Exception as exc:
            self.statusBar().showMessage(f"Chrome launch failed: {exc}", 7000)
            return
        self.show_page("Dashboard")
        self.statusBar().showMessage(f"Chrome capture active • opened {url}", 5000)

    def _start_chrome_capture(self, url):
        # A dedicated browser profile keeps CDP capture isolated from the user's
        # normal Chrome session. Every page in that profile is monitored.
        if self.chrome_capture:
            try:
                self.chrome_capture.stop()
                self.chrome_capture.wait(1200)
            except Exception:
                pass
            self.chrome_capture = None

        self.browser_records = []
        self.browser_row_map = {}
        self.history_table.setRowCount(0)
        self.history_count.setText("0 requests")
        self.dashboard_request.clear()
        self.dashboard_response.clear()

        port = find_free_port()
        proc, _port, profile = launch_chrome(url, port)
        self.chrome_process = proc
        self.chrome_profile = profile
        self.chrome_capture = ChromeCaptureThread(port, url, self)
        self.chrome_capture.transaction.connect(self._chrome_transaction)
        self.chrome_capture.updated.connect(self._chrome_transaction_updated)
        self.chrome_capture.error.connect(lambda msg: self.statusBar().showMessage(f"Chrome capture error: {msg}", 7000))
        self.chrome_capture.state.connect(lambda msg: self.statusBar().showMessage(msg, 3000))
        self.chrome_capture.start()

    @staticmethod
    def _header_block(headers):
        return "\n".join(f"{k}: {v}" for k, v in headers.items())

    @staticmethod
    def _request_path(url):
        p=urlsplit(url)
        path=p.path or "/"
        return path + (("?" + p.query) if p.query else "")

    def _captured_request_text(self, rec):
        headers = dict(rec.request_headers)
        # Chrome's CDP request headers may omit the Host header. Add it for a
        # familiar Burp-like request representation.
        if not any(k.lower() == "host" for k in headers):
            headers = {"Host": urlsplit(rec.url).netloc, **headers}
        first = f"{rec.method} {self._request_path(rec.url)} HTTP/1.1"
        head = self._header_block(headers)
        return first + ("\n" + head if head else "") + "\n\n" + (rec.request_body or "")

    def _captured_response_text(self, rec):
        status = rec.status or 0
        phrase = rec.status_text or ""
        first = f"HTTP/1.1 {status} {phrase}".rstrip()
        head = self._header_block(rec.response_headers)
        body = rec.response_body or ("\n[response body unavailable]" if status else "")
        return first + ("\n" + head if head else "") + "\n\n" + body

    def _chrome_transaction(self, rec: CapturedTransaction):
        key=(rec.tab_id, rec.request_id)
        if key in self.browser_row_map:
            return self._chrome_transaction_updated(rec)
        self.browser_row_map[key] = len(self.browser_records)
        self.browser_records.append(rec)
        row=self.history_table.rowCount()
        self.history_table.insertRow(row)
        self.browser_row_map[key]=row
        self._fill_history_row(row, rec)
        self.history_count.setText(f"{len(self.browser_records)} requests")

    def _chrome_transaction_updated(self, rec: CapturedTransaction):
        key=(rec.tab_id, rec.request_id)
        row=self.browser_row_map.get(key)
        if row is None:
            return self._chrome_transaction(rec)
        self.browser_records[row if row < len(self.browser_records) else -1] = rec
        self._fill_history_row(row, rec)
        if self.history_table.currentRow() == row:
            self._show_captured_transaction(rec)

    def _fill_history_row(self, row, rec):
        from datetime import datetime as _dt
        params = urlsplit(rec.url).query
        values=[
            rec.method, rec.url, "Yes" if params else "",
            str(rec.status) if rec.status else "…",
            str(rec.response_size) if rec.response_size else "—",
            rec.mime_type or "—", "", "",
            _dt.now().strftime("%H:%M:%S"),
        ]
        for col,val in enumerate(values):
            item=self.history_table.item(row,col)
            if item is None:
                item=QTableWidgetItem()
                self.history_table.setItem(row,col,item)
            item.setText(str(val))
        self.history_table.resizeRowToContents(row)

    def _show_captured_transaction(self, rec):
        self.dashboard_request.setPlainText(self._captured_request_text(rec))
        self.dashboard_response.setPlainText(self._captured_response_text(rec))

    def closeEvent(self, event):
        if self.chrome_capture:
            try:
                self.chrome_capture.stop()
                self.chrome_capture.wait(800)
            except Exception:
                pass
        super().closeEvent(event)

    def analyzer(self):
        s, outer = self.page()
        outer.setContentsMargins(26, 24, 26, 28)
        outer.setSpacing(14)

        # Analyzer header / command strip
        header = QFrame(); header.setObjectName("analyzerHeader")
        hl = QHBoxLayout(header); hl.setContentsMargins(18, 14, 18, 14); hl.setSpacing(12)
        title_box = QVBoxLayout(); title_box.setSpacing(3)
        eyebrow = QLabel("WEB ANALYZER  •  V3.0")
        eyebrow.setStyleSheet(f"color:{CYAN};font-size:10px;font-weight:800;letter-spacing:2px;")
        self.analyzer_title = QLabel("Traffic-driven security analysis")
        self.analyzer_title.setStyleSheet("font-size:24px;font-weight:800;")
        self.analyzer_target = QLabel("Target: —  •  Source: Dashboard HTTP History")
        self.analyzer_target.setStyleSheet(f"color:{MUTED};font-size:11px;")
        title_box.addWidget(eyebrow); title_box.addWidget(self.analyzer_title); title_box.addWidget(self.analyzer_target)
        hl.addLayout(title_box, 1)

        status_box = QFrame(); status_box.setObjectName("analyzerStatus")
        sl = QHBoxLayout(status_box); sl.setContentsMargins(11, 7, 11, 7); sl.setSpacing(7)
        self.analyzer_status_dot = QLabel("●")
        self.analyzer_status_dot.setStyleSheet(f"color:{GREEN};font-size:12px;")
        self.analyzer_status = QLabel("READY")
        self.analyzer_status.setStyleSheet(f"color:{GREEN};font-size:10px;font-weight:800;letter-spacing:1px;")
        sl.addWidget(self.analyzer_status_dot); sl.addWidget(self.analyzer_status)
        hl.addWidget(status_box)

        self.analyzer_start = QPushButton("▶  START ANALYSIS")
        self.analyzer_start.setObjectName("primary"); self.analyzer_start.setMinimumSize(152, 42)
        self.analyzer_start.clicked.connect(self.start_analysis); hl.addWidget(self.analyzer_start)
        self.analyzer_stop = QPushButton("■  STOP"); self.analyzer_stop.setMinimumSize(76, 42); self.analyzer_stop.setEnabled(False)
        self.analyzer_stop.clicked.connect(self.stop_analysis); hl.addWidget(self.analyzer_stop)
        outer.addWidget(header)

        # Metrics
        metric_row = QHBoxLayout(); metric_row.setSpacing(10)
        self.metrics = {}
        metric_specs = [
            ("REQUESTS", "0", CYAN), ("ENDPOINTS", "0", GREEN), ("PARAMETERS", "0", GOLD),
            ("CONFIRMED", "0", PURPLE), ("TESTED", "0", GOLD), ("SECRETS", "0", CYAN),
        ]
        for title, value, accent in metric_specs:
            card = Metric(title, value, accent); metric_row.addWidget(card, 1); self.metrics[title] = card
        outer.addLayout(metric_row)

        workspace = QSplitter(Qt.Horizontal); workspace.setChildrenCollapsible(False); workspace.setHandleWidth(6)
        workspace.setStyleSheet(f"QSplitter::handle{{background:#101d34;}} QSplitter::handle:hover{{background:{CYAN};}}")

        # Left analyzer module navigation
        left = QFrame(); left.setObjectName("panel")
        ll = QVBoxLayout(left); ll.setContentsMargins(12, 12, 12, 12); ll.setSpacing(8)
        nav_head = QLabel("ANALYZER MODULES"); nav_head.setStyleSheet(f"color:{MUTED};font-size:10px;font-weight:800;letter-spacing:2px;padding:4px 6px;")
        ll.addWidget(nav_head)
        self.analyzer_nav = QListWidget(); self.analyzer_nav.setObjectName("analyzerNav"); self.analyzer_nav.setSpacing(4)
        modules = [
            ("Overview", "◎"), ("Site Map", "⌘"), ("Network", "⇄"), ("Secrets", "◆"),
            ("WebSockets", "◌"), ("Web Forms", "▤"), ("JavaScript", "JS"),
            ("Technologies", "◇"), ("Cookies", "○"), ("Payloads", "⚡"),
        ]
        for name, glyph in modules:
            item = QListWidgetItem(f"  {glyph:<2}  {name}"); item.setData(Qt.UserRole, name); self.analyzer_nav.addItem(item)
        self.analyzer_nav.setCurrentRow(0)
        self.analyzer_nav.currentRowChanged.connect(self._analyzer_module_changed)
        ll.addWidget(self.analyzer_nav, 1)

        summary = QFrame(); summary.setObjectName("card")
        ql = QVBoxLayout(summary); ql.setContentsMargins(12, 12, 12, 12); ql.setSpacing(6)
        ql.addWidget(QLabel("FINDINGS SUMMARY"))
        self.summary_confirmed = QLabel("●  Confirmed     0"); self.summary_confirmed.setStyleSheet(f"color:{RED};font-size:11px;font-weight:700;")
        self.summary_tested = QLabel("●  Tested          0"); self.summary_tested.setStyleSheet(f"color:{GOLD};font-size:11px;font-weight:700;")
        self.summary_not_confirmed = QLabel("●  Not confirmed   0"); self.summary_not_confirmed.setStyleSheet(f"color:{MUTED};font-size:11px;font-weight:700;")
        for x in [self.summary_confirmed, self.summary_tested, self.summary_not_confirmed]: ql.addWidget(x)
        ll.addWidget(summary)
        workspace.addWidget(left)

        # Main content: overview or module data
        right = QFrame(); right.setObjectName("analyzerContent")
        rl = QVBoxLayout(right); rl.setContentsMargins(0, 0, 0, 0); rl.setSpacing(10)

        self.analyzer_stack = QStackedWidget(); self.analyzer_stack.setObjectName("analyzerStack")
        self.module_pages = {}
        for name in ["Overview","Site Map","Network","Secrets","JWT","Authorization","IDOR / BOLA","WebSockets","Web Forms","JavaScript","Technologies","Cookies","Payloads"]:
            page = self._build_analyzer_module_page(name); self.module_pages[name] = page; self.analyzer_stack.addWidget(page)
        rl.addWidget(self.analyzer_stack, 1)

        self.analyzer_log = QPlainTextEdit(); self.analyzer_log.setReadOnly(True); self.analyzer_log.setFixedHeight(104)
        self.analyzer_log.setPlaceholderText("Analysis log will appear here…")
        self.analyzer_log.setStyleSheet(f"background:#060d19;border:1px solid {BORDER};border-radius:10px;padding:8px;color:#8da0ba;font-family:DejaVu Sans Mono;font-size:10px;")
        rl.addWidget(self.analyzer_log)
        workspace.addWidget(right); workspace.setSizes([230, 980])
        outer.addWidget(workspace, 1)

        # Backward-compatible attributes used by existing functions.
        self.tabs = self.analyzer_stack
        self.table = self.module_pages["Network"].property("table_widget")
        self.payload_table = self.module_pages["Payloads"].property("table_widget")
        self.payload_status = self.module_pages["Payloads"].property("status_label")
        return s

    def _build_analyzer_module_page(self, name):
        page = QWidget(); vl = QVBoxLayout(page); vl.setContentsMargins(0, 0, 0, 0); vl.setSpacing(10)
        if name == "Overview":
            top = QFrame(); top.setObjectName("panel"); tl = QVBoxLayout(top); tl.setContentsMargins(16, 14, 16, 14); tl.setSpacing(8)
            row = QHBoxLayout(); title = QLabel("CONFIRMED FINDINGS"); title.setStyleSheet("font-size:15px;font-weight:800;"); row.addWidget(title); row.addStretch()
            self.finding_filter = QLineEdit(); self.finding_filter.setPlaceholderText("Filter findings…"); self.finding_filter.setFixedWidth(250); self.finding_filter.textChanged.connect(self._filter_findings); row.addWidget(self.finding_filter)
            tl.addLayout(row)
            hint = QLabel("Only evidence-backed results are marked CONFIRMED. Discoveries without proof remain TESTED / NOT CONFIRMED.")
            hint.setStyleSheet(f"color:{MUTED};font-size:10px;"); tl.addWidget(hint)
            self.finding_list = QListWidget(); self.finding_list.setObjectName("findingList"); self.finding_list.setSpacing(7); self.finding_list.itemClicked.connect(self._show_finding_detail)
            tl.addWidget(self.finding_list, 1); vl.addWidget(top, 1)
            self.finding_detail = QPlainTextEdit(); self.finding_detail.setReadOnly(True); self.finding_detail.setObjectName("findingDetail"); vl.addWidget(self.finding_detail, 1)
            return page
        if name == "Network":
            table=self._make_table(["METHOD","STATUS","URL","CONTENT TYPE","SIZE"]); table.cellDoubleClicked.connect(self.network_to_repeater); table.setContextMenuPolicy(Qt.CustomContextMenu); table.customContextMenuRequested.connect(self._network_context_menu); vl.addWidget(table); page.setProperty("table_widget", table); return page
        if name == "JWT":
            note=QLabel("JWT is analyzed from observed Authorization headers and cookies. Decoding is informational; no cryptographic weakness is inferred without evidence."); note.setWordWrap(True); note.setStyleSheet(f"color:{MUTED};font-size:10px;"); vl.addWidget(note)
            table=self._make_table(["LOCATION","ALGORITHM","CLAIMS","ENDPOINT","TOKEN"]); vl.addWidget(table,1); page.setProperty("table_widget", table); return page
        if name == "Authorization":
            table=self._make_table(["TYPE","ENDPOINT","SOURCE"]); vl.addWidget(table,1); page.setProperty("table_widget", table); return page
        if name == "IDOR / BOLA":
            note=QLabel("Object references are observations only. IDOR/BOLA is not confirmed from an identifier alone."); note.setWordWrap(True); note.setStyleSheet(f"color:{MUTED};font-size:10px;"); vl.addWidget(note)
            table=self._make_table(["TYPE","OBJECT REFERENCE","SOURCE"]); vl.addWidget(table,1); page.setProperty("table_widget", table); return page
        if name == "Payloads":
            note=QLabel("Controlled probes are generated only for observed input surfaces. A result is CONFIRMED only when concrete evidence is present."); note.setWordWrap(True); note.setStyleSheet(f"color:{MUTED};font-size:10px;"); vl.addWidget(note)
            table=self._make_table(["STATE","FAMILY","PARAMETER","PAYLOAD","STATUS","LENGTH","EVIDENCE","SOURCES"]); vl.addWidget(table,1); page.setProperty("table_widget", table)
            status=QLabel("Waiting for analysis…"); status.setStyleSheet(f"color:{MUTED};font-size:10px;"); vl.addWidget(status); page.setProperty("status_label", status); return page
        if name in {"Site Map","Secrets","WebSockets","Web Forms","JavaScript","Technologies","Cookies"}:
            table=self._make_table(["TYPE","VALUE","SOURCE"]); vl.addWidget(table,1); page.setProperty("table_widget", table); return page
        return page

    def _make_table(self, headers):
        table=QTableWidget(0,len(headers)); table.setHorizontalHeaderLabels(headers); table.setSelectionBehavior(QAbstractItemView.SelectRows); table.setSelectionMode(QAbstractItemView.SingleSelection); table.setAlternatingRowColors(False)
        hh=table.horizontalHeader()
        if len(headers)>1:
            hh.setSectionResizeMode(1,QHeaderView.Stretch)
            for i in range(len(headers)):
                if i != 1: hh.setSectionResizeMode(i,QHeaderView.ResizeToContents)
        else: hh.setSectionResizeMode(0,QHeaderView.Stretch)
        table.verticalHeader().setVisible(False); table.setWordWrap(False); return table

    def _analyzer_module_changed(self, row):
        if row < 0 or row >= self.analyzer_stack.count(): return
        self.analyzer_stack.setCurrentIndex(row)

    def _set_analyzer_status(self, state, color=GREEN):
        if hasattr(self, "analyzer_status"):
            self.analyzer_status.setText(state); self.analyzer_status.setStyleSheet(f"color:{color};font-size:10px;font-weight:800;letter-spacing:1px;")
            self.analyzer_status_dot.setStyleSheet(f"color:{color};font-size:12px;")

    def _module_table(self, name):
        return self.module_pages[name].property("table_widget")

    def _clear_module_table(self, name):
        t=self._module_table(name)
        if t: t.setRowCount(0)

    def _add_module_row(self, name, values):
        t=self._module_table(name)
        if not t: return
        row=t.rowCount(); t.insertRow(row)
        for c,v in enumerate(values): t.setItem(row,c,QTableWidgetItem(str(v)))

    def _populate_simple_module(self, name, items, source="analysis"):
        self._clear_module_table(name)
        for value in items: self._add_module_row(name, [name.upper(), value, source])

    def _filter_findings(self, text):
        q=text.strip().lower()
        for i in range(self.finding_list.count()):
            item=self.finding_list.item(i); item.setHidden(bool(q and q not in item.text().lower()))

    def _show_finding_detail(self, item):
        data=item.data(Qt.UserRole) or {}
        self.finding_detail.setPlainText(data.get("detail", item.text()))

    def _analyzer_log_line(self, line):
        if not hasattr(self, "analyzer_log"): return
        stamp=datetime.now().strftime("%H:%M:%S")
        self.analyzer_log.appendPlainText(f"[{stamp}] {line}")

    def stop_analysis(self):
        if self.worker and self.worker.isRunning():
            self.worker.requestInterruption()
            self._set_analyzer_status("STOPPING", GOLD)
            self.analyzer_stop.setEnabled(False)

    def start_analysis(self):
        records=list(self.browser_records or [])
        if not records:
            self.statusBar().showMessage("Analysis requires HTTP History. Open a target in Dashboard and generate traffic first.", 7000)
            return
        target=""
        for rec in records:
            url=str(getattr(rec, "url", "") or "")
            if url.lower().startswith(("http://", "https://")):
                target=url; break
        if not target:
            self.statusBar().showMessage("No HTTP/HTTPS target found in HTTP History.", 7000); return
        self.analyzer_target.setText(f"Target: {urlsplit(target).scheme}://{urlsplit(target).netloc}  •  Source: Dashboard HTTP History")
        self._set_analyzer_status("ANALYZING", GOLD); self.analyzer_start.setEnabled(False); self.analyzer_stop.setEnabled(True)
        self.analyzer_log.clear(); self._analyzer_log_line(f"Starting analysis from {len(records)} captured requests")
        for m in self.metrics.values(): m.setValue(0)
        for name in self.module_pages:
            if name != "Overview": self._clear_module_table(name)
        self.finding_list.clear(); self.finding_detail.clear(); self.result=None
        self.worker=Worker(target, records); self.worker.line.connect(self._analyzer_log_line); self.worker.done.connect(self.analysis_done)
        self.worker.failed.connect(self._analysis_failed); self.worker.start()

    def _analysis_failed(self, message):
        self._set_analyzer_status("ERROR", RED); self.analyzer_start.setEnabled(True); self.analyzer_stop.setEnabled(False)
        self._analyzer_log_line(f"ERROR: {message}"); self.statusBar().showMessage(f"Analysis error: {message}", 7000)

    def analysis_done(self, r:AnalysisResult):
        self.result=r
        endpoint_set={urlunsplit((urlsplit(x.url).scheme,urlsplit(x.url).netloc,urlsplit(x.url).path,"", "")) for x in r.requests}
        params=set()
        for x in r.requests:
            params.update(k for k,_ in parse_qsl(urlsplit(x.url).query, keep_blank_values=True))
            ctype = next((v for k,v in x.request_headers.items() if str(k).lower() == "content-type"), "").lower()
            if x.request_body and "application/x-www-form-urlencoded" in ctype:
                params.update(k for k,_ in parse_qsl(x.request_body, keep_blank_values=True))
            elif x.request_body and "application/json" in ctype:
                try:
                    obj = __import__("json").loads(x.request_body)
                    if isinstance(obj, dict): params.update(obj.keys())
                except Exception:
                    pass
        confirmed=[]; tested=0
        not_confirmed=0
        for pr in r.payload_runs:
            tested += 1
            if getattr(pr, "state", "TESTED") == "CONFIRMED":
                confirmed.append(pr)
            else:
                not_confirmed += 1
        counts={
            "REQUESTS":len(r.requests), "ENDPOINTS":len(endpoint_set), "PARAMETERS":len(params),
            "CONFIRMED":len(confirmed), "TESTED":tested, "SECRETS":len(r.secrets),
            "JWT TOKENS":len(r.jwt_tokens), "IDOR SURFACES":len(r.idor_surfaces),
        }
        for key,val in counts.items(): self.metrics[key].setValue(val)
        self.summary_confirmed.setText(f"●  Confirmed     {len(confirmed)}"); self.summary_tested.setText(f"●  Tested          {tested}"); self.summary_not_confirmed.setText(f"●  Not confirmed   {not_confirmed}")

        nt=self._module_table("Network"); nt.setRowCount(0)
        for rec in r.requests:
            row=nt.rowCount(); nt.insertRow(row)
            vals=[rec.method,str(rec.status or "—"),rec.url,rec.content_type or "—",str(rec.size)]
            for c,v in enumerate(vals): nt.setItem(row,c,QTableWidgetItem(v))

        self._populate_simple_module("Site Map", r.site_map, "captured traffic")
        self._populate_simple_module("Secrets", r.secrets, "response / script evidence")
        self._populate_simple_module("WebSockets", r.websockets, "captured traffic")
        self._clear_module_table("Web Forms")
        for f in r.forms: self._add_module_row("Web Forms", [f.get("method",""), f.get("action",""), f"inputs={len(f.get('inputs',[]))}"])
        self._populate_simple_module("JavaScript", r.js_files, "captured HTML / network")
        self._populate_simple_module("Technologies", r.technologies, "headers / response signatures")
        self._populate_simple_module("Cookies", r.cookies, "captured headers")
        jt=self._module_table("JWT"); jt.setRowCount(0)
        for j in r.jwt_tokens:
            row=jt.rowCount(); jt.insertRow(row); values=[j.location,j.algorithm or "—", ", ".join(j.claims.keys()) or "—",j.endpoint,j.token_preview]
            for c,v in enumerate(values): jt.setItem(row,c,QTableWidgetItem(str(v)))
        at=self._module_table("Authorization"); at.setRowCount(0)
        for value in r.auth_surfaces: self._add_module_row("Authorization", ["AUTH SURFACE", value, "captured traffic"])
        it=self._module_table("IDOR / BOLA"); it.setRowCount(0)
        for value in r.idor_surfaces: self._add_module_row("IDOR / BOLA", ["OBJECT REFERENCE", value, "captured traffic"])

        pt=self._module_table("Payloads"); pt.setRowCount(0)
        for pr in r.payload_runs:
            state=getattr(pr, "state", "TESTED")
            row=pt.rowCount(); pt.insertRow(row)
            vals=[state,pr.family,pr.parameter,pr.payload,str(pr.status or "—"),str(pr.size or "—"),pr.evidence or pr.error or "No confirming evidence", " | ".join(pr.source_urls) if getattr(pr, "source_urls", None) else "—"]
            for c,v in enumerate(vals): pt.setItem(row,c,QTableWidgetItem(v))
        self.payload_status.setText(f"{len(r.payload_runs)} controlled probes • {len(confirmed)} confirmed by explicit evidence")

        self.finding_list.clear()
        for pr in confirmed:
            item=QListWidgetItem(f"CONFIRMED   {pr.family}   •   {pr.method}   {pr.parameter or '—'}")
            detail=(
                f"CONFIRMED FINDING\n\n"
                f"Family: {pr.family}\nMethod: {pr.method}\nEndpoint: {pr.url}\n"
                f"Parameter: {pr.parameter or '—'}\nPayload: {pr.payload}\n\n"
                f"Baseline: {pr.baseline_status} / {pr.baseline_size} bytes\n"
                f"Test: {pr.status} / {pr.size} bytes\n"
                f"Diff: {pr.diff_summary}\n\n"
                f"Evidence:\n✓ {pr.evidence}\n\n"
                f"BASELINE REQUEST\n{pr.baseline_request}\n\n"
                f"TEST REQUEST\n{pr.test_request}\n\n"
                f"This result is marked CONFIRMED only because the family-specific evidence rule matched the observed response."
            )
            item.setData(Qt.UserRole, {"detail":detail}); self.finding_list.addItem(item)
        if self.finding_list.count()==0:
            self.finding_list.addItem("No evidence-backed findings from captured traffic.")
            self.finding_detail.setPlainText("No CONFIRMED finding was produced. Discovered surfaces remain available in the modules.")
        self._analyzer_log_line(f"Completed: {len(r.requests)} requests • {len(confirmed)} confirmed • {tested} tested")
        self._set_analyzer_status("COMPLETE", GREEN); self.analyzer_start.setEnabled(True); self.analyzer_stop.setEnabled(False)
        self.analyzer_stack.setCurrentIndex(0); self.analyzer_nav.setCurrentRow(0)
        self.statusBar().showMessage(f"Analysis complete • {len(r.requests)} captured requests analyzed", 7000)

    def history_selected(self):
        if not hasattr(self,"history_table"):
            return
        row=self.history_table.currentRow()
        if row < 0:
            return
        # Live Chrome traffic takes precedence over the old static analyzer data.
        if row < len(self.browser_records):
            self._show_captured_transaction(self.browser_records[row])
            return
        if self.result and row < len(self.result.requests):
            rec=self.result.requests[row]
            self.dashboard_request.setPlainText(f"{rec.method} {rec.url}\n\nTarget: {self.result.target}")
            self.dashboard_response.setPlainText(f"HTTP {rec.status}\n\nContent-Type: {rec.content_type}\nLength: {rec.size}")

    def history_to_repeater(self,row,_col=0):
        if row < 0:
            return
        if row < len(self.browser_records):
            self.open_captured_in_repeater(self.browser_records[row])
            return
        if self.result and row < len(self.result.requests):
            self.network_to_repeater(row,0)

    def _history_context_menu(self, pos):
        row = self.history_table.rowAt(pos.y())
        if row < 0:
            return
        self.history_table.selectRow(row)
        menu = QMenu(self)
        send = menu.addAction("Send to Repeater")
        send.setIconVisibleInMenu(False)
        menu.addSeparator()
        copy_url = menu.addAction("Copy URL")
        action = menu.exec(self.history_table.viewport().mapToGlobal(pos))
        if action == send:
            self.history_to_repeater(row, 0)
        elif action == copy_url:
            rec = self.browser_records[row] if row < len(self.browser_records) else None
            if rec:
                QApplication.clipboard().setText(rec.url)
            elif self.result and row < len(self.result.requests):
                QApplication.clipboard().setText(self.result.requests[row].url)

    def _network_context_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        self.table.selectRow(row)
        menu = QMenu(self)
        send = menu.addAction("Send to Repeater")
        copy_url = menu.addAction("Copy URL")
        action = menu.exec(self.table.viewport().mapToGlobal(pos))
        if action == send:
            self.network_to_repeater(row, 0)
        elif action == copy_url and self.result and row < len(self.result.requests):
            QApplication.clipboard().setText(self.result.requests[row].url)

    def fill_tab(self,index,text):
        w=self.tabs.widget(index);ed=getattr(w,"_editor",None)
        if ed:ed.setPlainText(text)

    def network_to_repeater(self,row,_col=0):
        if not self.result or row<0 or row>=len(self.result.requests):return
        self.open_analyzer_record_in_repeater(self.result.requests[row])

    def open_analyzer_record_in_repeater(self, rec):
        parsed=urlsplit(rec.url)
        host=parsed.netloc
        path=parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        headers = {"Host": host, "User-Agent": "CTF-Exploit-Workbench/2.0", "Accept": "*/*"}
        request=(f"{rec.method} {path} HTTP/1.1\n"
                 + "\n".join(f"{k}: {v}" for k,v in headers.items()) + "\n\n")
        self.open_repeater(rec.method, rec.url, request, "")

    def open_captured_in_repeater(self, rec: CapturedTransaction):
        request = self._captured_request_text(rec)
        self.open_repeater(rec.method, rec.url, request, "")

    def _new_repeater_session(self, method="GET", url="", request="", response=""):
        return {
            "method": method if method in ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"] else "GET",
            "url": url,
            "request": request,
            "response": response,
            "response_pretty": response,
            "request_view": "Pretty",
            "response_view": "Pretty",
            "status": "—",
            "time": "—",
            "size": "—",
        }

    def open_repeater(self,method,url,headers,body):
        if not hasattr(self,"rep_tabs"):
            self.show_page("Repeater")
        request = headers
        if not headers.upper().startswith(method.upper()+" "):
            parsed=urlsplit(url)
            host=parsed.netloc
            path=parsed.path or "/"
            if parsed.query:path += "?"+parsed.query
            request=f"{method} {path} HTTP/2\nHost: {host}\n"+headers
        if body:
            request += ("\n" if not request.endswith("\n") else "") + "\n" + body
        self.new_repeater_tab(method,url,request,activate=True)

    def repeater(self):
        root = QWidget(); root.setObjectName("repeaterRoot")
        l = QVBoxLayout(root); l.setContentsMargins(14, 10, 14, 12); l.setSpacing(8)

        self.rep_sessions = []
        self.rep_history = []
        self.rep_history_index = -1
        self.rep_active_thread = None
        self.rep_request_editor = None
        self.rep_response_editors = {}
        self.rep_response_html = None

        tabs_bar = QFrame(); tabs_bar.setObjectName("repTabBar"); tabs_bar.setFixedHeight(44)
        tb = QHBoxLayout(tabs_bar); tb.setContentsMargins(0, 0, 0, 0); tb.setSpacing(8)
        self.rep_tabs = QTabWidget(); self.rep_tabs.setObjectName("repTabs")
        self.rep_tabs.setDocumentMode(True); self.rep_tabs.setMovable(True); self.rep_tabs.setTabsClosable(True)
        self.rep_tabs.setUsesScrollButtons(False); self.rep_tabs.setElideMode(Qt.ElideRight)
        self.rep_tabs.tabCloseRequested.connect(self.close_repeater_tab)
        self.rep_tabs.currentChanged.connect(self.switch_repeater_tab)
        tb.addWidget(self.rep_tabs, 1)
        self.rep_plus = QPushButton("+"); self.rep_plus.setObjectName("repPlus"); self.rep_plus.setFixedSize(36, 36); self.rep_plus.setToolTip("New request")
        self.rep_plus.clicked.connect(lambda: self.new_repeater_tab()); tb.addWidget(self.rep_plus, 0, Qt.AlignVCenter)
        l.addWidget(tabs_bar)

        action = QFrame(); action.setObjectName("repToolbar"); action.setFixedHeight(56)
        ab = QHBoxLayout(action); ab.setContentsMargins(8, 7, 8, 7); ab.setSpacing(6)
        self.rep_send = QPushButton("Send"); self.rep_send.setObjectName("primary"); self.rep_send.setFixedHeight(40); self.rep_send.setMinimumWidth(78)
        self.rep_send.setToolTip("Send request (Ctrl+Enter)"); self.rep_send.clicked.connect(self.send_repeater); ab.addWidget(self.rep_send)
        self.rep_cancel = QPushButton("Cancel"); self.rep_cancel.setFixedHeight(40); self.rep_cancel.setMinimumWidth(78); self.rep_cancel.setEnabled(False)
        self.rep_cancel.clicked.connect(self.cancel_repeater); ab.addWidget(self.rep_cancel)
        gear = QPushButton("⚙"); gear.setFixedSize(40, 40); gear.setToolTip("Repeater settings")
        gear.clicked.connect(lambda: self.statusBar().showMessage("HTTP client: httpx • TLS verification disabled", 3000)); ab.addWidget(gear)
        sep1 = QFrame(); sep1.setFrameShape(QFrame.VLine); sep1.setFixedWidth(1); sep1.setStyleSheet(f"background:{BORDER}; margin:7px 2px;"); ab.addWidget(sep1)
        self.rep_back = QPushButton("‹"); self.rep_back.setFixedSize(38, 40); self.rep_back.setToolTip("Previous response")
        self.rep_back.clicked.connect(lambda: self.navigate_repeater(-1)); self.rep_back.setEnabled(False); ab.addWidget(self.rep_back)
        self.rep_forward = QPushButton("›"); self.rep_forward.setFixedSize(38, 40); self.rep_forward.setToolTip("Next response")
        self.rep_forward.clicked.connect(lambda: self.navigate_repeater(1)); self.rep_forward.setEnabled(False); ab.addWidget(self.rep_forward)
        sep2 = QFrame(); sep2.setFrameShape(QFrame.VLine); sep2.setFixedWidth(1); sep2.setStyleSheet(f"background:{BORDER}; margin:7px 6px;"); ab.addWidget(sep2)
        target_box = QFrame(); target_box.setObjectName("repTargetBox"); target_layout = QHBoxLayout(target_box); target_layout.setContentsMargins(10, 0, 10, 0); target_layout.setSpacing(7)
        target_icon = QLabel("◎"); target_icon.setStyleSheet(f"color:{CYAN}; font-size:13px; font-weight:700;"); target_layout.addWidget(target_icon)
        self.rep_target_hint = QLabel("Target: —"); self.rep_target_hint.setStyleSheet(f"color:{TEXT}; font-size:11px;"); target_layout.addWidget(self.rep_target_hint)
        ab.addWidget(target_box, 1)
        self.rep_engine = QLabel("HTTP client  •  TLS verify off"); self.rep_engine.setStyleSheet(f"color:{MUTED}; font-size:10px;"); self.rep_engine.setAlignment(Qt.AlignRight | Qt.AlignVCenter); ab.addWidget(self.rep_engine)
        l.addWidget(action)

        split = QSplitter(Qt.Horizontal); split.setObjectName("repSplit"); split.setChildrenCollapsible(False); split.setHandleWidth(5)
        split.setStyleSheet(f"QSplitter#repSplit::handle{{background:#101d34; margin:5px 0; border-radius:2px;}} QSplitter#repSplit::handle:hover{{background:{CYAN};}}")

        def make_pane(title, badge_text, response=False):
            frame = QFrame(); frame.setObjectName("repPane")
            lay = QVBoxLayout(frame); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(0)
            header = QFrame(); header.setObjectName("repPaneHeader"); header.setFixedHeight(38)
            h = QHBoxLayout(header); h.setContentsMargins(12, 0, 12, 0)
            lab = QLabel(title); lab.setStyleSheet("font-size:12px;font-weight:800;"); h.addWidget(lab); h.addStretch()
            badge = QLabel(badge_text); badge.setStyleSheet(f"color:{CYAN if not response else MUTED};font-weight:800;font-size:10px;"); h.addWidget(badge)
            lay.addWidget(header)
            return frame, lay, badge

        req, rv, self.rep_method_badge = make_pane("Request", "GET")
        self.rep_request_views = QTabWidget(); self.rep_request_views.setObjectName("repRequestViews"); self.rep_request_views.setDocumentMode(True); self.rep_request_views.setUsesScrollButtons(False)
        # Build all request editors before connecting currentChanged. QTabWidget can
        # emit currentChanged immediately when the first tab is inserted.
        self.rep_request_pretty = QPlainTextEdit(); self._style_code_editor(self.rep_request_pretty)
        self.rep_request_raw = QPlainTextEdit(); self._style_code_editor(self.rep_request_raw)
        self.rep_request_hex = QPlainTextEdit(); self._style_code_editor(self.rep_request_hex); self.rep_request_hex.setReadOnly(True)
        self.rep_request_views.addTab(self.rep_request_pretty, "Pretty")
        self.rep_request_views.addTab(self.rep_request_raw, "Raw")
        self.rep_request_views.addTab(self.rep_request_hex, "Hex")
        self.rep_request_pretty.textChanged.connect(lambda: self._rep_editor_changed("Pretty"))
        self.rep_request_views.currentChanged.connect(self.repeater_request_view_changed)
        rv.addWidget(self.rep_request_views, 1)
        reqfoot = QFrame(); reqfoot.setObjectName("repFooter"); reqfoot.setFixedHeight(30)
        q = QHBoxLayout(reqfoot); q.setContentsMargins(12, 0, 12, 0)
        self.rep_request_info = QLabel("Request ready"); self.rep_request_info.setStyleSheet(f"color:{MUTED};font-size:10px;"); q.addWidget(self.rep_request_info); q.addStretch(); rv.addWidget(reqfoot)
        split.addWidget(req)

        res, sv, self.rep_status_badge = make_pane("Response", "—", response=True)
        self.rep_response_views = QTabWidget(); self.rep_response_views.setObjectName("repResponseViews"); self.rep_response_views.setDocumentMode(True); self.rep_response_views.setUsesScrollButtons(False)
        # Build all response widgets before connecting currentChanged for the same
        # reason as the request side.
        self.rep_response_pretty = QPlainTextEdit(); self._style_code_editor(self.rep_response_pretty); self.rep_response_pretty.setReadOnly(True)
        self.rep_response_raw = QPlainTextEdit(); self._style_code_editor(self.rep_response_raw); self.rep_response_raw.setReadOnly(True)
        self.rep_response_hex = QPlainTextEdit(); self._style_code_editor(self.rep_response_hex); self.rep_response_hex.setReadOnly(True)
        self.rep_response_render = QTextBrowser(); self.rep_response_render.setOpenExternalLinks(True); self.rep_response_render.setStyleSheet('QTextBrowser{background:#050d1a;border:0;padding:12px;font-family:"DejaVu Sans";}')
        self.rep_response_views.addTab(self.rep_response_pretty, "Pretty")
        self.rep_response_views.addTab(self.rep_response_raw, "Raw")
        self.rep_response_views.addTab(self.rep_response_hex, "Hex")
        self.rep_response_views.addTab(self.rep_response_render, "Render")
        self.rep_response_views.currentChanged.connect(self.repeater_response_view_changed)
        sv.addWidget(self.rep_response_views, 1)
        resfoot = QFrame(); resfoot.setObjectName("repFooter"); resfoot.setFixedHeight(30)
        q = QHBoxLayout(resfoot); q.setContentsMargins(12, 0, 12, 0)
        self.rep_response_info = QLabel("No response yet"); self.rep_response_info.setStyleSheet(f"color:{MUTED};font-size:10px;"); q.addWidget(self.rep_response_info); q.addStretch(); sv.addWidget(resfoot)
        split.addWidget(res)
        split.setSizes([1, 1])
        l.addWidget(split, 1)

        self.new_repeater_tab(activate=True)
        return root

    def _style_code_editor(self, editor):
        editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        editor.setFont(QFont("DejaVu Sans Mono",10))
        editor.setTabStopDistance(32)
        editor.setStyleSheet(f"QPlainTextEdit{{background:#050d1a;border:0;border-radius:0;padding:10px;color:#c9d8ec;selection-background-color:#174b77;}}")

    def _request_placeholder(self):
        return ("GET / HTTP/2\n"
                "Host: target.example\n"
                "User-Agent: CTF-Exploit-Workbench/1.0\n"
                "Accept: */*\n")

    def new_repeater_tab(self, method="GET", url="", request="", response="", activate=True):
        if not hasattr(self,"rep_tabs"): return
        session=self._new_repeater_session(method,url,request or self._request_placeholder(),response)
        self.rep_sessions.append(session)
        index=self.rep_tabs.addTab(QWidget(), str(len(self.rep_sessions)))
        self.rep_tabs.setTabToolTip(index,"Repeater request")
        if activate: self.rep_tabs.setCurrentIndex(index)
        else: self._load_repeater_session(session)
        self._refresh_repeater_tab_labels()

    def close_repeater_tab(self,index):
        if self.rep_tabs.count() <= 1:
            self.rep_sessions[0]=self._snapshot_repeater_session()
            self._load_repeater_session(self.rep_sessions[0])
            return
        current=self.rep_tabs.currentIndex()
        if 0 <= current < len(self.rep_sessions): self.rep_sessions[current]=self._snapshot_repeater_session()
        self.rep_tabs.removeTab(index)
        if 0 <= index < len(self.rep_sessions): self.rep_sessions.pop(index)
        self._refresh_repeater_tab_labels()

    def _refresh_repeater_tab_labels(self):
        for i in range(self.rep_tabs.count()): self.rep_tabs.setTabText(i, str(i+1))

    def _snapshot_repeater_session(self):
        if not hasattr(self,"rep_request_pretty"): return self._new_repeater_session()
        return {
            "method": self.rep_method_badge.text() if hasattr(self,"rep_method_badge") else "GET",
            "url": self.rep_target_hint.text().replace("Target: ","",1) if hasattr(self,"rep_target_hint") else "",
            "request": self.rep_request_pretty.toPlainText(),
            "response": self.rep_response_raw.toPlainText(),
            "response_pretty": self.rep_response_pretty.toPlainText(),
            "request_view": self.rep_request_views.tabText(self.rep_request_views.currentIndex()),
            "response_view": self.rep_response_views.tabText(self.rep_response_views.currentIndex()),
            "status": self.rep_status_badge.text(),
            "time": getattr(self,"_rep_last_time","—"),
            "size": getattr(self,"_rep_last_size","—"),
        }

    def switch_repeater_tab(self,index):
        if index < 0 or index >= len(self.rep_sessions): return
        # Persist old tab before loading new one.
        if getattr(self,"_rep_loaded_index",None) is not None and self._rep_loaded_index != index:
            old=self._rep_loaded_index
            if 0 <= old < len(self.rep_sessions): self.rep_sessions[old]=self._snapshot_repeater_session()
        self._load_repeater_session(self.rep_sessions[index]); self._rep_loaded_index=index

    def _load_repeater_session(self, session):
        self._rep_loading=True
        try:
            self.rep_request_pretty.setPlainText(session.get("request") or self._request_placeholder())
            self.rep_request_raw.setPlainText(session.get("request") or self._request_placeholder())
            self.rep_request_hex.setPlainText(self._to_hex(session.get("request") or self._request_placeholder()))
            response=session.get("response") or ""
            pretty=session.get("response_pretty") or response
            self.rep_response_raw.setPlainText(response)
            self.rep_response_pretty.setPlainText(pretty)
            self.rep_response_hex.setPlainText(self._to_hex(response))
            self.rep_response_render.setHtml(self._render_http_response(response))
            self.rep_method_badge.setText(session.get("method") or "GET")
            target=session.get("url") or self._extract_url_from_request(session.get("request") or "")
            self.rep_target_hint.setText("Target: " + (target or "—"))
            self.rep_status_badge.setText(session.get("status") or "—")
            self.rep_request_info.setText("Request ready")
            self.rep_response_info.setText("No response yet" if not response else f"{session.get('size','—')} bytes • {session.get('time','—')}")
        finally:
            self._rep_loading=False

    def repeater_request_view_changed(self,index):
        if getattr(self,"_rep_loading",False) or getattr(self,"_rep_view_syncing",False): return
        self._rep_view_syncing = True
        try:
            if index == 2:
                text=self.rep_request_raw.toPlainText() or self.rep_request_pretty.toPlainText()
                self.rep_request_hex.setPlainText(self._to_hex(text))
            elif index == 1:
                self.rep_request_raw.setPlainText(self.rep_request_pretty.toPlainText())
            else:
                text=self.rep_request_raw.toPlainText() or self.rep_request_pretty.toPlainText()
                if self.rep_request_pretty.toPlainText() != text:
                    self.rep_request_pretty.setPlainText(text)
        finally:
            self._rep_view_syncing = False

    def _rep_editor_changed(self, view_name):
        if getattr(self,"_rep_loading",False) or getattr(self,"_rep_view_syncing",False): return
        text=self.rep_request_pretty.toPlainText()
        self.rep_request_hex.setPlainText(self._to_hex(text))
        method,url=self._request_method_and_url(text)
        self.rep_method_badge.setText(method)
        self.rep_target_hint.setText("Target: " + (url or "—"))
        self.rep_request_info.setText(f"{len(text.encode('utf-8',errors='ignore'))} bytes")

    def repeater_response_view_changed(self,index):
        if index==0:
            self.rep_response_pretty.setPlainText(self.rep_response_pretty.toPlainText())
        elif index==2:
            self.rep_response_hex.setPlainText(self._to_hex(self.rep_response_raw.toPlainText()))
        elif index==3:
            self.rep_response_render.setHtml(self._render_http_response(self.rep_response_raw.toPlainText()))

    def _to_hex(self,text):
        data=text.encode("utf-8",errors="replace")
        lines=[]
        for i in range(0,len(data),16):
            chunk=data[i:i+16]
            hx=" ".join(f"{b:02x}" for b in chunk)
            asc="".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08x}  {hx:<47}  |{asc}|")
        return "\n".join(lines)

    def _request_method_and_url(self,text):
        lines=text.splitlines(); method="GET"; path=""; host=""
        if lines:
            first=lines[0].split()
            if first: method=first[0].upper()
            if len(first)>1: path=first[1]
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host=line.split(":",1)[1].strip(); break
        if path.startswith("http://") or path.startswith("https://"): url=path
        elif host: url="https://"+host+(path if path.startswith("/") else "/"+path)
        else: url=path
        return method,url

    def _extract_url_from_request(self,text):
        return self._request_method_and_url(text)[1]

    def _render_http_response(self, raw):
        if not raw:return "<div style='color:#7f91aa;padding:16px'>No response yet.</div>"
        parts=raw.split("\n\n",1); head=parts[0]; body=parts[1] if len(parts)>1 else ""
        escaped=html.escape(body)
        ctype=""
        for line in head.splitlines():
            if line.lower().startswith("content-type:"): ctype=line.split(":",1)[1].strip().lower()
        if "html" in ctype:
            try: preview=body
            except Exception: preview=escaped
            return "<style>body{font-family:DejaVu Sans;background:#071023;color:#d8e3f3;padding:18px}a{color:#4bb8ff}</style>"+preview
        return f"<pre style='white-space:pre-wrap;color:#c9d8ec;font-family:DejaVu Sans Mono'>{escaped}</pre>"

    def _parse_repeater_request(self,text, fallback_url=""):
        text=text.replace("\r\n","\n")
        parts=text.split("\n\n",1); head=parts[0]; body=parts[1] if len(parts)>1 else ""
        lines=head.splitlines(); method="GET"; target=fallback_url; headers={}
        if lines:
            first=lines[0].split()
            if len(first)>=2 and first[0].upper() in ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"]:
                method=first[0].upper(); path=first[1]
            else:path="/"
        for line in lines[1:]:
            if ":" in line:
                k,v=line.split(":",1); headers[k.strip()]=v.strip()
        host=headers.get("Host","").strip()
        if path.startswith("http://") or path.startswith("https://"):
            target=path
        elif host:
            target="https://"+host+(path if path.startswith("/") else "/"+path)
        if not target:
            raise ValueError("No target URL: add a Host header or open a valid URL from the Dashboard")
        return method,target,headers,body

    def send_repeater(self):
        if self.rep_active_thread and self.rep_active_thread.isRunning(): return
        text=self.rep_request_pretty.toPlainText().strip()
        try:
            method,url,headers,body=self._parse_repeater_request(text,self.rep_target_hint.text().replace("Target: ","",1).strip())
        except Exception as e:
            self.rep_response_raw.setPlainText("REQUEST ERROR\n\n"+str(e)); self.rep_response_views.setCurrentIndex(0); return
        self.rep_target_hint.setText("Target: "+url); self.rep_method_badge.setText(method)
        self.rep_send.setEnabled(False); self.rep_cancel.setEnabled(True); self.rep_status_badge.setText("…"); self.rep_request_info.setText("Sending request…")
        self.rep_active_thread=RepeaterWorker(method,url,headers,body)
        self.rep_active_thread.done.connect(self.repeater_done)
        self.rep_active_thread.failed.connect(self.repeater_failed)
        self.rep_active_thread.cancelled.connect(self.repeater_cancelled)
        self.rep_active_thread.start()

    def cancel_repeater(self):
        if self.rep_active_thread and self.rep_active_thread.isRunning():
            self.rep_active_thread.stop_requested=True
            self.rep_cancel.setEnabled(False)
            self.rep_request_info.setText("Cancelling request…")
            self.statusBar().showMessage("Repeater: cancellation requested", 2500)

    def repeater_cancelled(self):
        self.rep_send.setEnabled(True)
        self.rep_cancel.setEnabled(False)
        self.rep_status_badge.setText("CANCEL")
        self.rep_request_info.setText("Request cancelled")
        self.statusBar().showMessage("Repeater request cancelled", 3000)

    def repeater_done(self,payload):
        self.rep_send.setEnabled(True); self.rep_cancel.setEnabled(False)
        if getattr(self.rep_active_thread,"stop_requested",False): return
        raw,status,elapsed,size,final_url=payload
        self.rep_response_raw.setPlainText(raw)
        self.rep_response_pretty.setPlainText(self._pretty_http_response(raw))
        self.rep_response_hex.setPlainText(self._to_hex(raw))
        self.rep_response_render.setHtml(self._render_http_response(raw))
        self.rep_response_views.setCurrentIndex(0)
        self.rep_status_badge.setText(status)
        self.rep_response_info.setText(f"{size} bytes • {elapsed} ms • {final_url}")
        self.rep_request_info.setText(f"{self.rep_method_badge.text()} request complete")
        self._rep_last_time=f"{elapsed} ms"; self._rep_last_size=f"{size} bytes"
        self._push_repeater_history(self._snapshot_repeater_session())
        self.statusBar().showMessage(f"Repeater: {status} • {size} bytes • {elapsed} ms",5000)

    def repeater_failed(self,error):
        self.rep_send.setEnabled(True); self.rep_cancel.setEnabled(False)
        self.rep_response_raw.setPlainText("REQUEST ERROR\n\n"+error); self.rep_response_pretty.setPlainText("REQUEST ERROR\n\n"+error); self.rep_response_hex.setPlainText(self._to_hex(error)); self.rep_response_views.setCurrentIndex(0); self.rep_status_badge.setText("ERR"); self.rep_response_info.setText("Request failed"); self.rep_request_info.setText("Request error"); self.statusBar().showMessage("Repeater request failed",5000)

    def _pretty_http_response(self,raw):
        if "\n\n" not in raw:return raw
        head,body=raw.split("\n\n",1)
        lines=head.splitlines()
        grouped=[]; current=[]
        for line in lines:
            if not line.strip(): continue
            grouped.append(line)
        return "\n".join(grouped)+"\n\n"+body

    def _push_repeater_history(self,session):
        self.rep_history=self.rep_history[:self.rep_history_index+1]
        self.rep_history.append(session)
        self.rep_history_index=len(self.rep_history)-1
        self._update_repeater_nav()

    def navigate_repeater(self,direction):
        if not self.rep_history:
            return
        idx=max(0,min(len(self.rep_history)-1,self.rep_history_index+direction))
        self.rep_history_index=idx
        session=self.rep_history[idx]
        self._rep_loading=True
        try:
            request=session.get("request","")
            response=session.get("response","")
            self.rep_request_pretty.setPlainText(request)
            self.rep_request_raw.setPlainText(request)
            self.rep_request_hex.setPlainText(self._to_hex(request))
            self.rep_response_raw.setPlainText(response)
            self.rep_response_pretty.setPlainText(session.get("response_pretty") or response)
            self.rep_response_hex.setPlainText(self._to_hex(response))
            self.rep_response_render.setHtml(self._render_http_response(response))
            self.rep_status_badge.setText(session.get("status","—"))
            self.rep_method_badge.setText(session.get("method") or self._request_method_and_url(request)[0])
            self.rep_target_hint.setText("Target: "+(session.get("url") or self._extract_url_from_request(request) or "—"))
            self.rep_request_info.setText("Request history")
            self.rep_response_info.setText(f"{session.get('size','—')} • {session.get('time','—')}")
        finally:
            self._rep_loading=False
        self._update_repeater_nav()

    def _update_repeater_nav(self):
        self.rep_back.setEnabled(self.rep_history_index>0); self.rep_forward.setEnabled(0<=self.rep_history_index<len(self.rep_history)-1)

    def workflow(self):
        # Visual workflow builder inspired by the reference: node library + canvas + properties.
        root = QWidget()
        root.setObjectName("workflowRoot")
        main = QHBoxLayout(root)
        main.setContentsMargins(18, 18, 18, 18)
        main.setSpacing(12)

        # Left node library
        library = QFrame(); library.setObjectName("card"); library.setFixedWidth(220)
        lv = QVBoxLayout(library); lv.setContentsMargins(14, 14, 14, 14); lv.setSpacing(8)
        head = QLabel("Nodes Library"); head.setStyleSheet("font-size:15px;font-weight:800;")
        sub = QLabel("Drag-ready building blocks")
        sub.setStyleSheet(f"color:{MUTED};font-size:10px;")
        lv.addWidget(head); lv.addWidget(sub); lv.addSpacing(6)
        self.workflow_buttons = {}
        node_defs = [
            ("＋", "Custom node", "Customize a node in the right panel", "custom"),
            ("⚡", "Trigger", "Initiate workflow", "trigger"),
            ("▶", "Action", "Perform a task", "action"),
            ("◉", "Notification", "Send status or notifications", "notification"),
            ("☷", "Conditional", "Branch the workflow", "conditional"),
            ("◷", "Delay", "Pause the workflow", "delay"),
            ("A", "User Task", "Assign a manual step", "task"),
            ("↻", "Loop", "Repeat a set of actions", "loop"),
            ("↗", "Sub-process", "Embed another workflow", "subprocess"),
            ("⇄", "Parallel", "Run multiple branches", "parallel"),
            ("◇", "Decision", "Route the workflow", "decision"),
            ("⊕", "Merge", "Merge branches", "merge"),
        ]
        for glyph, label, desc, kind in node_defs:
            b = QPushButton(f"{glyph}   {label}")
            b.setToolTip(desc); b.setProperty("workflow_kind", kind)
            b.setStyleSheet(f"QPushButton{{text-align:left;padding:9px 10px;border-radius:8px;background:#071326;border:1px solid #132544;color:{TEXT};}} QPushButton:hover{{border-color:{CYAN};background:#0b1f39;}}")
            b.clicked.connect(lambda _, k=kind, lab=label: self.add_workflow_node(k, lab))
            self.workflow_buttons[kind] = b; lv.addWidget(b)
        lv.addStretch()
        main.addWidget(library)

        # Center workflow canvas
        center = QFrame(); center.setObjectName("card")
        cv = QVBoxLayout(center); cv.setContentsMargins(10, 10, 10, 10); cv.setSpacing(8)
        toolbar = QHBoxLayout()
        start = QPushButton("▶  Run from Start"); start.setObjectName("primary"); start.clicked.connect(self.run_workflow_preview)
        toolbar.addWidget(start)
        toolbar.addWidget(QPushButton("＋  Add node", clicked=lambda: self.add_workflow_node("custom", "Custom node")))
        toolbar.addStretch()
        zoom_minus = QPushButton("−"); zoom_plus = QPushButton("＋"); fit = QPushButton("Fit")
        zoom_minus.clicked.connect(lambda: self.workflow_view.scale(0.9, 0.9)); zoom_plus.clicked.connect(lambda: self.workflow_view.scale(1.1, 1.1)); fit.clicked.connect(self.fit_workflow)
        toolbar.addWidget(zoom_minus); toolbar.addWidget(zoom_plus); toolbar.addWidget(fit)
        cv.addLayout(toolbar)
        self.workflow_scene = QGraphicsScene(self)
        self.workflow_scene.setSceneRect(0, 0, 1800, 1050)
        self.workflow_view = QGraphicsView(self.workflow_scene)
        self.workflow_view.setRenderHints(self.workflow_view.renderHints())
        self.workflow_view.setDragMode(QGraphicsView.ScrollHandDrag)
        self.workflow_view.setBackgroundBrush(QColor("#06101f"))
        self.workflow_view.setFrameShape(QFrame.NoFrame)
        cv.addWidget(self.workflow_view, 1)
        main.addWidget(center, 1)

        # Right properties panel
        props = QFrame(); props.setObjectName("card"); props.setFixedWidth(300)
        pv = QVBoxLayout(props); pv.setContentsMargins(16, 16, 16, 16); pv.setSpacing(10)
        ph = QHBoxLayout(); ptitle = QLabel("Properties"); ptitle.setStyleSheet("font-size:15px;font-weight:800;"); ph.addWidget(ptitle); ph.addStretch(); pv.addLayout(ph)
        tabs = QTabWidget(); general = QWidget(); gv = QFormLayout(general); gv.setContentsMargins(0, 10, 0, 0)
        self.wf_name = QLineEdit("Decision"); self.wf_desc = QLineEdit("Route the workflow"); self.wf_status = QComboBox(); self.wf_status.addItems(["Active", "Draft", "Disabled"])
        gv.addRow("Title", self.wf_name); gv.addRow("Description", self.wf_desc); gv.addRow("Status", self.wf_status)
        tabs.addTab(general, "Properties")
        widgets = QWidget(); wv = QVBoxLayout(widgets); wv.addWidget(QLabel("Node configuration")); self.wf_config = QPlainTextEdit(); self.wf_config.setPlaceholderText("Node settings will appear here…"); wv.addWidget(self.wf_config); tabs.addTab(widgets, "Widgets")
        pv.addWidget(tabs, 1)
        apply_btn = QPushButton("Apply changes"); apply_btn.clicked.connect(self.apply_workflow_properties); pv.addWidget(apply_btn)
        main.addWidget(props)

        # Seed canvas with a clean reference workflow.
        self.workflow_nodes = []
        self.workflow_edges = []
        self._wf_counter = 0
        self.seed_workflow()
        return root

    def _workflow_node_color(self, kind):
        return {"trigger":"#0b6ea8", "action":"#0d3c67", "conditional":"#0c4f52", "decision":"#0c4f52", "notification":"#2d3c69", "delay":"#273a5b", "custom":"#1a3556"}.get(kind, "#142944")

    def add_workflow_node(self, kind="custom", label="Custom node", pos=None):
        if not hasattr(self, "workflow_scene"): return
        self._wf_counter += 1
        node = QGraphicsRectItem(0, 0, 220, 100)
        node.setBrush(QBrush(QColor(self._workflow_node_color(kind))))
        node.setPen(QPen(QColor("#31527d"), 1.2))
        node.setFlag(QGraphicsItem.ItemIsMovable, True); node.setFlag(QGraphicsItem.ItemIsSelectable, True)
        x, y = pos if pos else (100 + (self._wf_counter % 4) * 270, 100 + ((self._wf_counter // 4) % 3) * 160)
        node.setPos(x, y)
        node.kind = kind; node.label = label
        title = self.workflow_scene.addText(label)
        title.setDefaultTextColor(QColor(TEXT)); title.setFont(QFont("DejaVu Sans", 11, QFont.Bold)); title.setParentItem(node); title.setPos(12, 12)
        desc = self.workflow_scene.addText({"trigger":"Initiate workflow", "action":"Perform a task", "conditional":"Branch the workflow", "decision":"Route the workflow"}.get(kind, "Customize node in the right panel"))
        desc.setDefaultTextColor(QColor(MUTED)); desc.setFont(QFont("DejaVu Sans", 8)); desc.setParentItem(node); desc.setPos(12, 38)
        port = self.workflow_scene.addEllipse(207, 42, 9, 9, QPen(QColor(CYAN)), QBrush(QColor(CYAN))); port.setParentItem(node)
        inport = self.workflow_scene.addEllipse(4, 42, 9, 9, QPen(QColor("#4d6b91")), QBrush(QColor("#4d6b91"))); inport.setParentItem(node)
        self.workflow_scene.addItem(node); self.workflow_nodes.append(node)
        node.mousePressEvent = self._wf_node_press(node)
        return node

    def _wf_node_press(self, node):
        def handler(event):
            self.wf_name.setText(getattr(node, "label", "Node")); self.wf_desc.setText("Route the workflow" if node.kind in ("decision","conditional") else "Perform a workflow step")
            QGraphicsRectItem.mousePressEvent(node, event)
        return handler

    def seed_workflow(self):
        # Compact visual equivalent of the reference: Start → HTTP Request → Decision → branches → Final price.
        a = self.add_workflow_node("trigger", "Start", (120, 180))
        b = self.add_workflow_node("action", "HTTP Request", (410, 180))
        c = self.add_workflow_node("decision", "Decision", (700, 180))
        d = self.add_workflow_node("action", "Children's discount -50%", (1030, 80))
        e = self.add_workflow_node("action", "Adult", (1030, 235))
        f = self.add_workflow_node("action", "Senior's discount -25%", (1030, 390))
        g = self.add_workflow_node("action", "Final price", (1370, 220))
        self._add_workflow_edge(a, b)
        self._add_workflow_edge(b, c)
        self._add_workflow_edge(c, d)
        self._add_workflow_edge(c, e)
        self._add_workflow_edge(c, f)
        self._add_workflow_edge(d, g)
        self._add_workflow_edge(e, g)
        self._add_workflow_edge(f, g)
        self.workflow_scene.selectionChanged.connect(self.workflow_selection_changed)
        self.fit_workflow()

    def _add_workflow_edge(self, source, target):
        sx = source.pos().x() + 220; sy = source.pos().y() + 50
        tx = target.pos().x(); ty = target.pos().y() + 50
        line = QGraphicsLineItem(sx, sy, tx, ty)
        line.setPen(QPen(QColor("#2b9a85"), 2))
        line.setZValue(-1)
        self.workflow_scene.addItem(line)
        self.workflow_edges.append(line)

    def workflow_selection_changed(self):
        items = self.workflow_scene.selectedItems()
        if items and hasattr(items[0], "label"):
            n = items[0]; self.wf_name.setText(n.label); self.wf_desc.setText("Route the workflow" if n.kind in ("decision","conditional") else "Perform a workflow step")

    def apply_workflow_properties(self):
        items = self.workflow_scene.selectedItems()
        if not items or not hasattr(items[0], "label"): return
        n = items[0]; n.label = self.wf_name.text().strip() or "Custom node"
        for child in n.childItems():
            if isinstance(child, QGraphicsTextItem):
                if child.pos().y() < 30: child.setPlainText(n.label); break

    def fit_workflow(self):
        if hasattr(self, "workflow_view") and hasattr(self, "workflow_scene"):
            self.workflow_view.fitInView(self.workflow_scene.itemsBoundingRect().adjusted(-80,-80,80,80), Qt.KeepAspectRatio)

    def run_workflow_preview(self):
        self.statusBar().showMessage("Workflow preview started from Start → HTTP Request → Decision → Final price", 5000)
    def show_page(self,name):
        for k,b in self.nav.items():b.setProperty("active",k==name);b.style().unpolish(b);b.style().polish(b)
        self.stack.setCurrentWidget(self.pages[name])
