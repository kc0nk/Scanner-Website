from __future__ import annotations
import html
from datetime import datetime
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit
import httpx
from PySide6.QtCore import Qt, QThread, Signal
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
        self.history_table.setMinimumHeight(110); self.history_table.itemSelectionChanged.connect(self.history_selected)

        hint=QLabel("Drag the divider between HTTP History and Request/Response to resize the history area. Drag column borders to resize columns.")
        hint.setStyleSheet(f"color:{MUTED};font-size:10px;"); hv.addWidget(hint)

        # Vertical splitter: the HTTP History table can be expanded/shrunk like Burp's history pane.
        history_splitter=QSplitter(Qt.Vertical)
        history_splitter.setChildrenCollapsible(False)
        history_splitter.setHandleWidth(8)
        history_splitter.setMinimumHeight(360)
        history_splitter.addWidget(self.history_table)

        details=QSplitter(Qt.Horizontal); details.setChildrenCollapsible(False); details.setMinimumHeight(180)
        req=QFrame(); req.setObjectName("panel"); rv=QVBoxLayout(req); rv.setContentsMargins(12,10,12,10); rv.addWidget(QLabel("REQUEST")); self.dashboard_request=QPlainTextEdit(); self.dashboard_request.setReadOnly(True); rv.addWidget(self.dashboard_request)
        resp=QFrame(); resp.setObjectName("panel"); sv=QVBoxLayout(resp); sv.setContentsMargins(12,10,12,10); sv.addWidget(QLabel("RESPONSE")); self.dashboard_response=QPlainTextEdit(); self.dashboard_response.setReadOnly(True); sv.addWidget(self.dashboard_response)
        details.addWidget(req); details.addWidget(resp); details.setSizes([500,500])
        history_splitter.addWidget(details)
        history_splitter.setSizes([420,260])
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

    def fill_tab(self,index,text):
        w=self.tabs.widget(index);ed=getattr(w,"_editor",None)
        if ed:ed.setPlainText(text)
    def network_to_repeater(self,row,_col):
        if not self.result or row>=len(self.result.requests):return
        rec=self.result.requests[row];self.open_repeater(rec.method,rec.url,"User-Agent: CTF-Exploit-Workbench/1.0\nAccept: */*\n","")
    def open_repeater(self,method,url,headers,body):
        self.show_page("Repeater");self.rep_method.setCurrentText(method if method in ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"] else "GET");self.rep_url.setText(url);self.rep_request.setPlainText(headers+(("\n\n"+body) if body else ""));self.rep_response.setPlainText("Ready — press Send to issue the request.")
    def repeater(self):
        s,l=self.page();self.title(l,"Manual Testing","Repeater","Edit a request, send it, and inspect the real response.")
        bar=QFrame();bar.setObjectName("card");bl=QHBoxLayout(bar);self.rep_method=QComboBox();self.rep_method.addItems(["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"]);bl.addWidget(self.rep_method);self.rep_url=QLineEdit();self.rep_url.setPlaceholderText("https://target.example/path");bl.addWidget(self.rep_url,1);send=QPushButton("⚡ SEND");send.setObjectName("primary");send.clicked.connect(self.send_repeater);bl.addWidget(send);l.addWidget(bar)
        split=QSplitter(Qt.Horizontal);req=QFrame();req.setObjectName("card");rv=QVBoxLayout(req);rv.addWidget(QLabel("REQUEST"));self.rep_request=QPlainTextEdit();self.rep_request.setPlainText("User-Agent: CTF-Exploit-Workbench/1.0\nAccept: */*");rv.addWidget(self.rep_request);res=QFrame();res.setObjectName("card");sv=QVBoxLayout(res);sv.addWidget(QLabel("RESPONSE"));self.rep_response=QPlainTextEdit();self.rep_response.setReadOnly(True);sv.addWidget(self.rep_response);split.addWidget(req);split.addWidget(res);split.setSizes([700,700]);l.addWidget(split,1);return s
    def send_repeater(self):
        url=self.rep_url.text().strip()
        if not url:return
        method=self.rep_method.currentText();raw=self.rep_request.toPlainText();parts=raw.split("\n\n",1);header_lines=parts[0].splitlines();body=parts[1] if len(parts)>1 else "";headers={}
        for line in header_lines:
            if ":" in line:
                k,v=line.split(":",1);headers[k.strip()]=v.strip()
        try:
            with httpx.Client(timeout=15,follow_redirects=True,verify=False) as c:
                r=c.request(method,url,headers=headers,content=body.encode() if body else None)
            text=f"HTTP {r.http_version} {r.status_code} {r.reason_phrase}\n\n"+"\n".join(f"{k}: {v}" for k,v in r.headers.items())+"\n\n"+r.text
            self.rep_response.setPlainText(text)
        except Exception as e:self.rep_response.setPlainText("REQUEST ERROR\n\n"+str(e))
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
