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

BG="#050b1a"; PANEL="#0b1428"; BORDER="#1a2a48"; TEXT="#d8e3f3"; MUTED="#7f91aa"; CYAN="#11c8ef"; PURPLE="#9b5cff"; RED="#ff4f78"; GREEN="#21d7a5"; GOLD="#f5b82e"
STYLE=f'''
*{{font-family:"DejaVu Sans"; color:{TEXT};}}
QMainWindow,QWidget{{background:{BG};}}
QLabel{{background:transparent;}}
QFrame#sidebar{{background:#070e1d; border-right:1px solid {BORDER};}}
QFrame#topbar{{background:#080f20; border-bottom:1px solid {BORDER};}}
QFrame#card,QFrame#panel{{background:{PANEL}; border:1px solid {BORDER}; border-radius:14px;}}
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
QHeaderView::section{{background:#0d182b; color:#8da0ba; border:0; border-bottom:1px solid {BORDER}; padding:10px;}}
QTableWidget{{gridline-color:#10203a;}}
QTabBar::tab{{background:#0b162b; border:1px solid {BORDER}; padding:10px 16px; margin-right:5px; border-radius:9px; color:#91a0b7;}}
QTabBar::tab:selected{{background:#103657; color:{CYAN}; border-color:#176383;}}
QScrollArea{{border:0;}}
'''

class Worker(QThread):
    done=Signal(object); failed=Signal(str); line=Signal(str)
    def __init__(self,target): super().__init__(); self.target=target
    def run(self):
        try:self.done.emit(WebAnalyzer().run(self.target,self.line.emit))
        except Exception as e:self.failed.emit(str(e))

class Metric(QFrame):
    def __init__(self,title,value,accent=CYAN):
        super().__init__(); self.setObjectName("card"); l=QVBoxLayout(self); l.setContentsMargins(20,16,20,16)
        a=QLabel(title.upper()); a.setStyleSheet(f"color:{MUTED};font-size:11px;letter-spacing:2px;")
        self.value=QLabel(str(value)); self.value.setStyleSheet(f"color:{accent};font-size:27px;font-weight:700;")
        l.addWidget(a);l.addWidget(self.value)
    def setValue(self,v):self.value.setText(str(v))

class RepeaterWorker(QThread):
    done=Signal(object); failed=Signal(str)
    def __init__(self, method, url, headers, body):
        super().__init__(); self.method=method; self.url=url; self.headers=headers; self.body=body; self.stop_requested=False
    def run(self):
        import time
        started=time.perf_counter()
        try:
            with httpx.Client(timeout=15,follow_redirects=True,verify=False) as c:
                r=c.request(self.method,self.url,headers=self.headers,content=self.body.encode() if self.body else None)
            elapsed=int((time.perf_counter()-started)*1000)
            status=f"{r.status_code} {r.reason_phrase}"
            raw=f"{r.http_version} {r.status_code} {r.reason_phrase}\n"+"\n".join(f"{k}: {v}" for k,v in r.headers.items())+"\n\n"+r.text
            self.done.emit((raw,status,elapsed,len(r.content),str(r.url)))
        except Exception as e:
            self.failed.emit(str(e))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle(f"CTF Exploit Workbench v{__version__}"); self.resize(1500,900); self.setStyleSheet(STYLE); self.result=None; self.worker=None
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
        if url:
            self.show_page("Web Analyzer")
            self.analyzer_target.setText(f"Target: {url}")
            self.target_edit = QLineEdit()
            self.target_edit.setText(url)

    def analyzer(self):
        s,l=self.page()
        # v1.0: keep the analyzer focused on artifacts. Target is supplied by Dashboard.
        grid=QGridLayout();self.metrics={};names=[("SITE MAP",CYAN),("NETWORK",CYAN),("SECRETS",PURPLE),("WEBSOCKETS",CYAN),("WEB FORMS",CYAN),("JS FILES",CYAN),("TECHNOLOGIES",CYAN),("STORAGE",CYAN),("COOKIES",CYAN)]
        for i,(n,c) in enumerate(names):self.metrics[n]=Metric(n,0,c);grid.addWidget(self.metrics[n],i//5,i%5)
        l.addLayout(grid)

        action=QFrame();action.setObjectName("card");al=QHBoxLayout(action);al.setContentsMargins(16,10,16,10)
        self.analyzer_target=QLabel("Target: —");self.analyzer_target.setStyleSheet(f"color:{MUTED};font-size:12px;")
        al.addWidget(self.analyzer_target,1)
        go=QPushButton("⚡  START ANALYSIS");go.setObjectName("primary");go.clicked.connect(self.start_analysis);al.addWidget(go)
        l.addWidget(action)

        self.tabs=QTabWidget()
        for n in ["Site Map","Network","Secrets","WebSockets","Web Forms","JS Files","Technologies","Storage","Cookies","Payloads"]:self.tabs.addTab(self.make_tab(n),n)
        l.addWidget(self.tabs,1);return s

    def make_tab(self,name):
        if name=="Network":
            w=QWidget();vl=QVBoxLayout(w);self.table=QTableWidget(0,5);self.table.setHorizontalHeaderLabels(["METHOD","STATUS","URL","CONTENT TYPE","SIZE"]);self.table.horizontalHeader().setSectionResizeMode(2,QHeaderView.Stretch);self.table.cellDoubleClicked.connect(self.network_to_repeater);vl.addWidget(self.table);return w
        if name=="Payloads":
            w=QWidget();vl=QVBoxLayout(w)
            note=QLabel("All payloads run automatically against discovered request surfaces. No payload selector.")
            note.setStyleSheet(f"color:{MUTED};font-size:12px;");vl.addWidget(note)
            self.payload_table=QTableWidget(0,7)
            self.payload_table.setHorizontalHeaderLabels(["FAMILY","PAYLOAD","METHOD","PARAMETER","STATUS","LENGTH","EVIDENCE"])
            self.payload_table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.payload_table.setAlternatingRowColors(False)
            ph=self.payload_table.horizontalHeader();ph.setSectionResizeMode(0,QHeaderView.ResizeToContents);ph.setSectionResizeMode(1,QHeaderView.Stretch);ph.setSectionResizeMode(2,QHeaderView.ResizeToContents);ph.setSectionResizeMode(3,QHeaderView.ResizeToContents);ph.setSectionResizeMode(4,QHeaderView.ResizeToContents);ph.setSectionResizeMode(5,QHeaderView.ResizeToContents);ph.setSectionResizeMode(6,QHeaderView.Stretch)
            self.payload_table.setMinimumHeight(260);vl.addWidget(self.payload_table,1)
            self.payload_status=QLabel("Waiting for analysis…");self.payload_status.setStyleSheet(f"color:{MUTED};font-size:11px;");vl.addWidget(self.payload_status)
            return w
        w=QWidget();vl=QVBoxLayout(w);ed=QPlainTextEdit();ed.setReadOnly(True);ed.setPlaceholderText(f"{name} artifacts will appear here...");w._editor=ed;vl.addWidget(ed);return w

    def start_analysis(self):
        target=self.target_edit.text().strip()
        if not target:return
        for m in self.metrics.values():m.setValue(0)
        self.table.setRowCount(0);self.tabs.setCurrentIndex(1);self.worker=Worker(target);self.worker.done.connect(self.analysis_done);self.worker.failed.connect(lambda e:self.statusBar().showMessage(f"Analysis error: {e}"));self.worker.start()
    def analysis_done(self,r:AnalysisResult):
        self.result=r;self.metrics["SITE MAP"].setValue(len(r.site_map));self.metrics["NETWORK"].setValue(len(r.requests));self.metrics["SECRETS"].setValue(len(r.secrets));self.metrics["WEB FORMS"].setValue(len(r.forms));self.metrics["JS FILES"].setValue(len(r.js_files));self.metrics["TECHNOLOGIES"].setValue(len(r.technologies));self.metrics["COOKIES"].setValue(len(r.cookies))
        for rec in r.requests:
            row=self.table.rowCount();self.table.insertRow(row)
            for col,val in enumerate([rec.method,str(rec.status),rec.url,rec.content_type,str(rec.size)]):self.table.setItem(row,col,QTableWidgetItem(val))
            hrow=self.history_table.rowCount(); self.history_table.insertRow(hrow)
            params=urlsplit(rec.url).query
            vals=[rec.method,rec.url,"Yes" if params else "",str(rec.status),str(rec.size),rec.content_type,"", "", datetime.now().strftime("%H:%M:%S")]
            for col,val in enumerate(vals): self.history_table.setItem(hrow,col,QTableWidgetItem(val))
        self.history_count.setText(f"{len(r.requests)} requests")
        self.fill_tab(0,"\n".join(r.site_map));self.fill_tab(2,"\n".join(r.secrets) or "No secret artifacts collected.");self.fill_tab(4,"\n".join(f"{x['method']} {x['action']}" for x in r.forms) or "No forms observed.");self.fill_tab(5,"\n".join(r.js_files) or "No JavaScript files observed.");self.fill_tab(6,"\n".join(r.technologies) or "No technology headers identified.");self.fill_tab(8,"\n".join(r.cookies) or "No cookies observed.")
        self.payload_table.setRowCount(0)
        for pr in r.payload_runs:
            row=self.payload_table.rowCount();self.payload_table.insertRow(row)
            vals=[pr.family,pr.payload,"GET",pr.parameter,str(pr.status),str(pr.size),pr.evidence or (pr.error if pr.error else "—")]
            for col,val in enumerate(vals):self.payload_table.setItem(row,col,QTableWidgetItem(val))
        self.payload_status.setText(f"Automatic payload execution: {len(r.payload_runs)} probes completed")
    def history_selected(self):
        if not hasattr(self,"history_table") or not self.result:return
        row=self.history_table.currentRow()
        if row < 0 or row >= len(self.result.requests):return
        rec=self.result.requests[row]
        self.dashboard_request.setPlainText(f"{rec.method} {rec.url}\n\nTarget: {self.result.target}")
        self.dashboard_response.setPlainText(f"HTTP {rec.status}\n\nContent-Type: {rec.content_type}\nLength: {rec.size}")

    def history_to_repeater(self,row,_col):
        if not self.result or row < 0 or row >= len(self.result.requests): return
        rec=self.result.requests[row]
        self.network_to_repeater(row,0)

    def fill_tab(self,index,text):
        w=self.tabs.widget(index);ed=getattr(w,"_editor",None)
        if ed:ed.setPlainText(text)
    def network_to_repeater(self,row,_col):
        if not self.result or row>=len(self.result.requests):return
        rec=self.result.requests[row]
        parsed=urlsplit(rec.url)
        host=parsed.netloc
        path=parsed.path or "/"
        if parsed.query:path += "?" + parsed.query
        request=(f"{rec.method} {path} HTTP/2\n"
                 f"Host: {host}\n"
                 f"User-Agent: CTF-Exploit-Workbench/1.0\n"
                 "Accept: */*\n")
        self.open_repeater(rec.method,rec.url,request,"")

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
        self.rep_active_thread.start()

    def cancel_repeater(self):
        if self.rep_active_thread and self.rep_active_thread.isRunning():
            self.rep_active_thread.stop_requested=True
            self.rep_cancel.setEnabled(False); self.rep_request_info.setText("Cancellation requested…")

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
        if not self.rep_history:return
        idx=max(0,min(len(self.rep_history)-1,self.rep_history_index+direction)); self.rep_history_index=idx
        s=self.rep_history[idx]; self.rep_request_pretty.setPlainText(s.get("request","")); self.rep_response_raw.setPlainText(s.get("response","")); self.rep_response_pretty.setPlainText(s.get("response_pretty",s.get("response",""))); self.rep_response_hex.setPlainText(self._to_hex(s.get("response",""))); self.rep_status_badge.setText(s.get("status","—")); self.rep_target_hint.setText("Target: "+(s.get("url") or "—")); self._update_repeater_nav()

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
