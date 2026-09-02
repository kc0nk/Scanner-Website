from __future__ import annotations
import html
from datetime import datetime
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit
import httpx
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import *
from app.version import __version__
from core.analyzer import WebAnalyzer, AnalysisResult
from core.payloads import PAYLOADS

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
        # Clean reference-style dashboard: compact welcome panel, then project URL input.
        hero=QFrame(); hero.setObjectName("panel")
        hl=QHBoxLayout(hero); hl.setContentsMargins(24,18,24,18); hl.setSpacing(18)

        left=QVBoxLayout(); left.setSpacing(7)
        tag=QLabel("●  SYSTEM ACTIVE")
        tag.setStyleSheet(f"color:{GREEN};background:#062c2a;border:1px solid #0d6157;border-radius:15px;padding:5px 10px;")
        tag.setFixedWidth(150)
        left.addWidget(tag)
        hi=QLabel("Hello, <font color='#3b9bff'>hackers01</font> 👋")
        hi.setStyleSheet("font-size:25px;font-weight:800;")
        left.addWidget(hi)
        hl.addLayout(left,1)

        divider=QFrame(); divider.setFrameShape(QFrame.VLine); divider.setFrameShadow(QFrame.Plain)
        divider.setStyleSheet(f"color:{BORDER};background:{BORDER};max-width:1px;")
        hl.addWidget(divider)

        p=QPushButton("↗  Open Project")
        p.setObjectName("primary")
        p.clicked.connect(lambda:self.show_page("Web Analyzer"))
        p.setMinimumWidth(155)
        hl.addWidget(p)
        l.addWidget(hero)

        url_card=QFrame(); url_card.setObjectName("card")
        ul=QVBoxLayout(url_card); ul.setContentsMargins(18,16,18,16); ul.setSpacing(9)
        label=QLabel("PROJECT URL")
        label.setStyleSheet(f"color:{MUTED};font-size:10px;font-weight:700;letter-spacing:2px;")
        ul.addWidget(label)
        row=QHBoxLayout(); row.setSpacing(10)
        self.dashboard_url=QLineEdit()
        self.dashboard_url.setPlaceholderText("https://target.example")
        self.dashboard_url.returnPressed.connect(self.open_dashboard_target)
        row.addWidget(self.dashboard_url,1)
        open_url=QPushButton("Open")
        open_url.setObjectName("primary")
        open_url.clicked.connect(self.open_dashboard_target)
        row.addWidget(open_url)
        ul.addLayout(row)
        l.addWidget(url_card)

        l.addStretch()
        return s

    def open_dashboard_target(self):
        url=self.dashboard_url.text().strip()
        if url:
            self.show_page("Web Analyzer")
            self.target_edit.setText(url)

    def analyzer(self):
        s,l=self.page();self.title(l,"Recon Engine","Web Analyzer","Map the target, inspect requests, then work with payloads manually.")
        bar=QFrame();bar.setObjectName("card");bl=QHBoxLayout(bar);self.target_edit=QLineEdit();self.target_edit.setPlaceholderText("https://target.example");bl.addWidget(self.target_edit,1);go=QPushButton("⚡  START ANALYSIS");go.setObjectName("primary");go.clicked.connect(self.start_analysis);bl.addWidget(go);l.addWidget(bar)
        grid=QGridLayout();self.metrics={};names=[("SITE MAP",CYAN),("NETWORK",CYAN),("SECRETS",PURPLE),("WEBSOCKETS",CYAN),("WEB FORMS",CYAN),("JS FILES",CYAN),("TECHNOLOGIES",CYAN),("STORAGE",CYAN),("COOKIES",CYAN)]
        for i,(n,c) in enumerate(names):self.metrics[n]=Metric(n,0,c);grid.addWidget(self.metrics[n],i//5,i%5)
        l.addLayout(grid);self.tabs=QTabWidget()
        for n in ["Site Map","Network","Secrets","WebSockets","Web Forms","JS Files","Technologies","Storage","Cookies","Payloads","AI ✨"]:self.tabs.addTab(self.make_tab(n),n)
        l.addWidget(self.tabs,1);return s

    def make_tab(self,name):
        if name=="Network":
            w=QWidget();vl=QVBoxLayout(w);self.table=QTableWidget(0,5);self.table.setHorizontalHeaderLabels(["METHOD","STATUS","URL","CONTENT TYPE","SIZE"]);self.table.horizontalHeader().setSectionResizeMode(2,QHeaderView.Stretch);self.table.cellDoubleClicked.connect(self.network_to_repeater);vl.addWidget(self.table);return w
        if name=="Payloads": return self.payload_tab()
        if name=="AI ✨":
            w=QWidget();vl=QVBoxLayout(w);self.ai=QTextBrowser();self.ai.setHtml("<h2>✨ AI Copilot</h2><p>Analysis notes will appear here after a scan.</p>");vl.addWidget(self.ai);return w
        w=QWidget();vl=QVBoxLayout(w);ed=QPlainTextEdit();ed.setReadOnly(True);ed.setPlaceholderText(f"{name} artifacts will appear here...");w._editor=ed;vl.addWidget(ed);return w

    def payload_tab(self):
        w=QWidget();v=QVBoxLayout(w)
        info=QLabel("Payload Library · select a family and send a payload into Repeater for controlled testing.");info.setStyleSheet(f"color:{MUTED};");v.addWidget(info)
        row=QHBoxLayout();self.payload_family=QComboBox();self.payload_family.addItems(PAYLOADS.keys());self.payload_family.currentTextChanged.connect(self.refresh_payloads);row.addWidget(self.payload_family,1);self.payload_combo=QComboBox();row.addWidget(self.payload_combo,2);btn=QPushButton("Send to Repeater");btn.setObjectName("primary");btn.clicked.connect(self.payload_to_repeater);row.addWidget(btn);v.addLayout(row)
        self.payload_preview=QPlainTextEdit();self.payload_preview.setReadOnly(True);v.addWidget(self.payload_preview,1);self.refresh_payloads(self.payload_family.currentText());return w
    def refresh_payloads(self,family):
        if not hasattr(self,"payload_combo"):return
        self.payload_combo.clear();self.payload_combo.addItems(PAYLOADS.get(family,[]));self.payload_combo.currentTextChanged.connect(self._preview_payload)
        self._preview_payload(self.payload_combo.currentText())
    def _preview_payload(self,p):
        if hasattr(self,"payload_preview"):self.payload_preview.setPlainText(p or "")

    def start_analysis(self):
        target=self.target_edit.text().strip()
        if not target:return
        for m in self.metrics.values():m.setValue(0)
        self.table.setRowCount(0);self.tabs.setCurrentIndex(1);self.worker=Worker(target);self.worker.done.connect(self.analysis_done);self.worker.failed.connect(lambda e:self.ai.setHtml(f"<h2>Analysis error</h2><p>{html.escape(e)}</p>"));self.worker.start()
    def analysis_done(self,r:AnalysisResult):
        self.result=r;self.metrics["SITE MAP"].setValue(len(r.site_map));self.metrics["NETWORK"].setValue(len(r.requests));self.metrics["SECRETS"].setValue(len(r.secrets));self.metrics["WEB FORMS"].setValue(len(r.forms));self.metrics["JS FILES"].setValue(len(r.js_files));self.metrics["TECHNOLOGIES"].setValue(len(r.technologies));self.metrics["COOKIES"].setValue(len(r.cookies));self.m2.setValue(1);self.m3.setValue(len(r.requests))
        for rec in r.requests:
            row=self.table.rowCount();self.table.insertRow(row)
            for col,val in enumerate([rec.method,str(rec.status),rec.url,rec.content_type,str(rec.size)]):self.table.setItem(row,col,QTableWidgetItem(val))
        self.fill_tab(0,"\n".join(r.site_map));self.fill_tab(2,"\n".join(r.secrets) or "No secret artifacts collected.");self.fill_tab(4,"\n".join(f"{x['method']} {x['action']}" for x in r.forms) or "No forms observed.");self.fill_tab(5,"\n".join(r.js_files) or "No JavaScript files observed.");self.fill_tab(6,"\n".join(r.technologies) or "No technology headers identified.");self.fill_tab(8,"\n".join(r.cookies) or "No cookies observed.");self.ai.setHtml(f"<h2>Analysis complete</h2><p><b>{html.escape(r.target)}</b></p><p>Collected {len(r.requests)} network requests and {len(r.site_map)} in-scope URLs.</p>")
    def fill_tab(self,index,text):
        w=self.tabs.widget(index);ed=getattr(w,"_editor",None)
        if ed:ed.setPlainText(text)
    def network_to_repeater(self,row,_col):
        if not self.result or row>=len(self.result.requests):return
        rec=self.result.requests[row];self.open_repeater(rec.method,rec.url,"User-Agent: CTF-Exploit-Workbench/1.0\nAccept: */*\n","")
    def payload_to_repeater(self):
        if not self.result or not self.result.requests:return
        rec=self.result.requests[0];payload=self.payload_combo.currentText();url=rec.url
        sp=urlsplit(url);qs=parse_qsl(sp.query,keep_blank_values=True)
        if qs: qs[0]=(qs[0][0],payload);url=urlunsplit((sp.scheme,sp.netloc,sp.path, urlencode(qs),sp.fragment))
        else: url=url + ("&" if "?" in url else "?") + "input=" + payload
        self.open_repeater(rec.method,url,"User-Agent: CTF-Exploit-Workbench/1.0\nAccept: */*\n","")
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
        s,l=self.page();self.title(l,"Workflow","Workflow","Target → Discover → Analyze → Test → Review.")
        for num,name,desc in [("01","TARGET","Define the authorized target and scope."),("02","DISCOVER","Map pages, requests, forms, scripts and technologies."),("03","ANALYZE","Select an observed request and choose a payload family when testing is appropriate."),("04","TEST / REVIEW","Send the edited request through Repeater and inspect the real response.")]:
            card=QFrame();card.setObjectName("card");row=QHBoxLayout(card);row.setContentsMargins(22,18,22,18);n=QLabel(num);n.setFixedSize(46,46);n.setAlignment(Qt.AlignCenter);n.setStyleSheet(f"background:#0b2b48;border:1px solid #14516d;border-radius:12px;color:{CYAN};font-size:16px;font-weight:800;");row.addWidget(n);v=QVBoxLayout();h=QLabel(name);h.setStyleSheet("font-size:15px;font-weight:800;");d=QLabel(desc);d.setStyleSheet(f"color:{MUTED};font-size:12px;");v.addWidget(h);v.addWidget(d);row.addLayout(v);row.addStretch();l.addWidget(card)
        l.addStretch();return s
    def show_page(self,name):
        for k,b in self.nav.items():b.setProperty("active",k==name);b.style().unpolish(b);b.style().polish(b)
        self.stack.setCurrentWidget(self.pages[name])
