from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QPoint, QUrl
from PySide6.QtGui import QAction, QPixmap
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QSizePolicy,
    QVBoxLayout,
    QComboBox,
    QLineEdit,
    QListView,
    QMenu,
    QPlainTextEdit,
    QSplitter,
    QWidget,
    QStackedWidget,
)

from app.version import __version__
from core.chrome_capture import ChromeCaptureThread, launch_chrome
from core.scope import is_in_scope, normalize_scope

ROOT = Path(__file__).resolve().parents[1]
LOGO = ROOT / "assets" / "kconk_logo.png"

# Fixed reference canvas. The navbar is built against this exact width.
DESIGN_WIDTH = 1366
DESIGN_HEIGHT = 704
NAVBAR_HEIGHT = 56

BG = "#06110d"
NAV_BG = "#07130f"
NAV_BG_ACTIVE = "#0d2118"
LINE = "#284437"
LINE_HOVER = "#3e5f4d"
TEXT = "#eee5cc"
TEXT_DIM = "#9da69b"
GOLD = "#d8b56a"
GOLD_BRIGHT = "#f0d18b"
GREEN = "#7fa888"

STYLE = f"""
QMainWindow, QWidget {{
    background: {BG};
    color: {TEXT};
    font-family: 'DejaVu Sans';
}}
QLabel {{
    background: transparent;
}}
QScrollArea {{
    border: 0;
    background: {BG};
}}
QScrollBar:vertical {{
    width: 11px;
    background: {BG};
}}
QScrollBar::handle:vertical {{
    background: #294938;
    border-radius: 5px;
    min-height: 45px;
}}
QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{ height: 0px; }}
QScrollBar:horizontal {{
    height: 11px;
    background: {BG};
}}
QScrollBar::handle:horizontal {{
    background: #294938;
    border-radius: 5px;
    min-width: 45px;
}}
QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {{ width: 0px; }}

QFrame#navbar {{
    background: {NAV_BG};
    border: 0;
}}
QWidget#navRow {{
    background: {NAV_BG};
}}
QFrame#navBottomLine {{
    background: {LINE};
    border: 0;
}}
QFrame#navDivider {{
    background: {LINE};
}}
QFrame#blankPage {{
    background: {BG};
    border: 0;
}}
QFrame#dashboardPage {{
    background: {BG};
    border: 0;
}}
QFrame#projectCard {{
    background: #081b14;
    border: 1px solid #315944;
    border-radius: 18px;
}}
QFrame#cardDivider {{
    background: #315944;
    border: 0;
}}
QWidget#navBrand, QWidget#navRail {{
    background: transparent;
}}

QFrame#proxyPage, QFrame#proxyWorkspace, QFrame#proxyContent {{
    background: {BG};
    border: 0;
}}
QFrame#proxySubbar {{
    background: {NAV_BG};
    border: 0;
}}
QFrame#proxySubLine {{ background: {LINE}; border: 0; }}
QFrame#proxyPanel {{
    background: #081b14;
    border: 1px solid #315944;
    border-radius: 10px;
}}
QPushButton#proxySubItem, QPushButton#proxySubActive {{
    background: transparent; border: 0; border-bottom: 2px solid transparent;
    color: {TEXT_DIM}; padding: 0 14px; font-size: 11px; font-weight: 700;
}}
QPushButton#proxySubItem:hover {{ background: {NAV_BG_ACTIVE}; color: {TEXT}; }}
QPushButton#proxySubActive {{ color: {GOLD_BRIGHT}; border-bottom: 2px solid {GOLD_BRIGHT}; background: {NAV_BG_ACTIVE}; }}
QPushButton#proxyAction {{ background: {NAV_BG}; color: {TEXT}; border: 1px solid {LINE}; border-radius: 7px; padding: 0 14px; }}
QPushButton#proxyAction:hover {{ background: {NAV_BG_ACTIVE}; color: {GOLD_BRIGHT}; border-color: {GOLD}; }}
QLineEdit#proxyScopeEdit {{ background: {BG}; color: {TEXT}; border: 1px solid {LINE}; border-radius: 7px; padding: 0 10px; }}
QLineEdit#proxyScopeEdit:focus {{ border-color: {GOLD}; }}
QTableWidget#proxyTable {{ background: #06110d; color: {TEXT}; border: 0; gridline-color: {LINE}; selection-background-color: {NAV_BG_ACTIVE}; }}
QTableWidget#proxyTable QHeaderView::section {{ background: {NAV_BG_ACTIVE}; color: {TEXT_DIM}; border: 0; padding: 7px; font-size: 10px; font-weight: 700; }}
QPushButton#navItem {{
    background: transparent;
    border: 0;
    border-bottom: 2px solid transparent;
    border-radius: 0px;
    color: {TEXT_DIM};
    padding: 0px 4px;
    margin: 0px;
    font-size: 11px;
    font-weight: 700;
    text-align: center;
    letter-spacing: 0px;
}}
QPushButton#navItem:hover {{
    background: {NAV_BG_ACTIVE};
    color: {TEXT};
}}
QPushButton#navItemActive {{
    background: {NAV_BG_ACTIVE};
    border: 0;
    border-bottom: 2px solid {GOLD_BRIGHT};
    border-radius: 0px;
    color: {GOLD_BRIGHT};
    padding: 0px 4px;
    margin: 0px;
    font-size: 11px;
    font-weight: 800;
    text-align: center;
}}
QPushButton#navUtility {{
    background: transparent;
    border: 0;
    border-radius: 7px;
    color: {GOLD};
    font-size: 16px;
    padding: 0px;
}}
QPushButton#navUtility:hover {{
    background: #10271c;
    color: {GOLD_BRIGHT};
}}
"""


class DraggableNavButton(QPushButton):
    """Fixed-size navbar button that can be dragged left/right to reorder."""

    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self._press_pos = QPoint()
        self._dragging = False

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._press_pos = event.position().toPoint()
            self._dragging = False
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if event.buttons() & Qt.LeftButton:
            delta = event.position().toPoint() - self._press_pos
            if abs(delta.x()) >= 8:
                self._dragging = True
                rail = self.parentWidget()
                if rail is not None and hasattr(rail, "reorder_button"):
                    rail.reorder_button(self, self.mapTo(rail, event.position().toPoint()).x())
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if self._dragging and event.button() == Qt.LeftButton:
            self.setDown(False)
            self._dragging = False
            event.accept()
            return
        super().mouseReleaseEvent(event)
        self._dragging = False


class NavRail(QWidget):
    """Horizontal fixed-width rail with reliable drag/drop reordering."""

    def __init__(self, items, select_callback, order_callback, parent=None):
        super().__init__(parent)
        self.setObjectName("navRail")
        self._select_callback = select_callback
        self._order_callback = order_callback
        self.layout_ = QHBoxLayout(self)
        self.layout_.setContentsMargins(0, 0, 0, 0)
        self.layout_.setSpacing(0)
        self.buttons = {}
        self.order = []

        for item_name, width in items:
            btn = DraggableNavButton(item_name, self)
            btn.setObjectName("navItem")
            btn.setFixedSize(width, NAVBAR_HEIGHT - 1)
            btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            btn.setFocusPolicy(Qt.NoFocus)
            btn.clicked.connect(lambda _checked=False, n=item_name: self._select_callback(n))
            self.buttons[item_name] = btn
            self.order.append(item_name)
            self.layout_.addWidget(btn)

        self._update_width()

    def set_order(self, order):
        order = [name for name in order if name in self.buttons]
        for name in self.order:
            if name not in order:
                order.append(name)
        self.order = order
        for name in self.order:
            self.layout_.removeWidget(self.buttons[name])
        for index, name in enumerate(self.order):
            self.layout_.insertWidget(index, self.buttons[name])
        self._update_width()
        self._order_callback(self.order.copy())

    def _update_width(self):
        self.setFixedSize(sum(self.buttons[name].width() for name in self.order), NAVBAR_HEIGHT - 1)

    def reorder_button(self, button, mouse_x: int):
        name = button.text()
        if name not in self.order:
            return

        current = self.order.index(name)
        # Remove the dragged item conceptually, then find the slot whose
        # midpoint is nearest to the cursor. Using actual widget geometry
        # avoids stale QLayout item indices during a live drag.
        remaining = [n for n in self.order if n != name]
        target = len(remaining)
        for idx, item_name in enumerate(remaining):
            other = self.buttons[item_name]
            center = other.geometry().center().x()
            if mouse_x < center:
                target = idx
                break

        new_order = remaining[:target] + [name] + remaining[target:]
        if new_order == self.order:
            return

        self.order = new_order
        self.layout_.removeWidget(button)
        self.layout_.insertWidget(target, button)
        self._update_width()
        self._order_callback(self.order.copy())




class MainWindow(QMainWindow):
    """KCONK UI shell. Navigation is intentionally rebuilt before modules."""

    # Exactly eight primary modules. Widths are intentionally fixed so the
    # navbar never reflows or clips when the desktop window is resized.
    NAV_ITEMS = [
        ("DASHBOARD", 100),
        ("WORKFLOW", 104),
        ("PROXY", 84),
        ("INTRUDER", 98),
        ("REPEATER", 98),
        ("SCANNING", 98),
        ("COLLABORATOR", 124),
        ("META WORKFLOW NC", 174),
    ]

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"KCONK Suite v{__version__}")
        self.setStyleSheet(STYLE)
        self.resize(DESIGN_WIDTH, DESIGN_HEIGHT)

        self.active_nav = "DASHBOARD"
        self.nav_buttons: dict[str, QPushButton] = {}
        self.chrome_process = None
        self.chrome_profile = None
        self.chrome_capture = None
        self.proxy_records = {}
        self.proxy_intercept_enabled = False
        self.proxy_intercepted = {}
        self.proxy_intercept_selected = None
        self.proxy_scope = ""

        viewport = QScrollArea()
        viewport.setWidgetResizable(False)
        viewport.setAlignment(Qt.AlignTop | Qt.AlignHCenter)
        viewport.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        viewport.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        canvas = QWidget()
        canvas.setFixedSize(DESIGN_WIDTH, DESIGN_HEIGHT)
        root = QVBoxLayout(canvas)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self.build_navbar())
        self.root_layout = root

        # Main module pages. Dashboard stays the landing page; Proxy gets its
        # own secondary navigation bar underneath the primary navbar.
        self.pages = QStackedWidget()
        self.pages.setObjectName("modulePages")
        self.pages.setFixedSize(DESIGN_WIDTH, DESIGN_HEIGHT - NAVBAR_HEIGHT)

        self.dashboard_page = self.build_dashboard()
        self.proxy_page = self.build_proxy()
        self.pages.addWidget(self.dashboard_page)
        self.pages.addWidget(self.proxy_page)
        root.addWidget(self.pages)

        viewport.setWidget(canvas)
        self.setCentralWidget(viewport)

        self.refresh_nav_state()


    def build_proxy(self) -> QFrame:
        """Proxy workspace with a dedicated secondary navigation bar."""
        page = QFrame()
        page.setObjectName("proxyPage")
        page.setFixedSize(DESIGN_WIDTH, DESIGN_HEIGHT - NAVBAR_HEIGHT)

        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        subbar = QFrame()
        subbar.setObjectName("proxySubbar")
        subbar.setFixedHeight(48)
        sub_layout = QHBoxLayout(subbar)
        sub_layout.setContentsMargins(18, 0, 18, 0)
        sub_layout.setSpacing(2)

        self.proxy_sub_buttons = {}
        for label in ("INTERCEPT", "HTTP HISTORY"):
            btn = QPushButton(label)
            btn.setObjectName("proxySubActive" if label == "INTERCEPT" else "proxySubItem")
            btn.setFixedHeight(48)
            btn.setMinimumWidth(128 if label == "INTERCEPT" else 150)
            btn.setFocusPolicy(Qt.NoFocus)
            btn.clicked.connect(lambda _=False, n=label: self.select_proxy_subtab(n))
            self.proxy_sub_buttons[label] = btn
            sub_layout.addWidget(btn)
        sub_layout.addStretch(1)
        outer.addWidget(subbar)

        line = QFrame()
        line.setObjectName("proxySubLine")
        line.setFixedHeight(1)
        outer.addWidget(line)

        scope_bar = QFrame()
        scope_bar.setObjectName("proxyPanel")
        scope_bar.setFixedHeight(58)
        sl = QHBoxLayout(scope_bar)
        sl.setContentsMargins(18, 8, 18, 8)
        sl.setSpacing(8)
        scope_title = QLabel("SCOPE")
        scope_title.setStyleSheet(f"font-size:10px;font-weight:800;color:{TEXT_DIM};")
        sl.addWidget(scope_title)
        scope_edit = QLineEdit()
        scope_edit.setPlaceholderText("https://target.example")
        scope_edit.setText(self.proxy_scope)
        scope_edit.setObjectName("proxyScopeEdit")
        scope_edit.setFixedHeight(34)
        self.proxy_scope_edit = scope_edit
        sl.addWidget(scope_edit, 1)
        apply_btn = QPushButton("APPLY")
        apply_btn.setObjectName("proxyAction")
        apply_btn.setFixedSize(76, 34)
        apply_btn.clicked.connect(self.apply_proxy_scope)
        sl.addWidget(apply_btn)
        self.proxy_scope_status = QLabel("NO SCOPE")
        self.proxy_scope_status.setMinimumWidth(110)
        self.proxy_scope_status.setAlignment(Qt.AlignCenter)
        sl.addWidget(self.proxy_scope_status)
        outer.addWidget(scope_bar)

        self.proxy_content = QStackedWidget()
        self.proxy_content.setObjectName("proxyContent")
        self.proxy_content.addWidget(self.build_proxy_intercept())
        self.proxy_content.addWidget(self.build_proxy_history())
        outer.addWidget(self.proxy_content)
        self.proxy_subtab = "INTERCEPT"
        return page

    def apply_proxy_scope(self) -> None:
        raw = self.proxy_scope_edit.text().strip() if hasattr(self, "proxy_scope_edit") else ""
        normalized = normalize_scope(raw)
        if raw and not normalized:
            self.proxy_scope_status.setText("INVALID SCOPE")
            self.proxy_scope_status.setStyleSheet("font-size:10px;font-weight:800;color:#d96b6b;")
            return
        self.proxy_scope = normalized
        if hasattr(self, "proxy_scope_edit"):
            self.proxy_scope_edit.setText(normalized)
        if normalized:
            self.proxy_scope_status.setText("IN SCOPE")
            self.proxy_scope_status.setStyleSheet(f"font-size:10px;font-weight:800;color:{GREEN};")
        else:
            self.proxy_scope_status.setText("NO SCOPE")
            self.proxy_scope_status.setStyleSheet(f"font-size:10px;font-weight:800;color:{TEXT_DIM};")
        capture = getattr(self, "chrome_capture", None)
        if capture is not None and capture.isRunning():
            capture.set_scope(normalized)
        # A scope change starts a clean capture view; stale traffic must never
        # appear to belong to the new target.
        self.proxy_records.clear()
        if hasattr(self, "proxy_history_table"):
            self.proxy_history_table.setRowCount(0)
        self.proxy_intercepted.clear()
        if hasattr(self, "proxy_intercept_table"):
            self.proxy_intercept_table.setRowCount(0)
        self.proxy_intercept_selected = None

    def _is_in_scope(self, url: str) -> bool:
        return is_in_scope(url, self.proxy_scope)

    def build_proxy_intercept(self) -> QFrame:
        page = QFrame()
        page.setObjectName("proxyWorkspace")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        header = QHBoxLayout()
        title = QLabel("Intercept")
        title.setStyleSheet(f"font-size:22px;font-weight:800;color:{GOLD_BRIGHT};")
        header.addWidget(title)
        header.addStretch(1)
        self.proxy_intercept_status = QLabel("Intercept is off")
        self.proxy_intercept_status.setStyleSheet(f"font-size:12px;color:{TEXT_DIM};")
        header.addWidget(self.proxy_intercept_status)
        layout.addLayout(header)

        controls = QFrame()
        controls.setObjectName("proxyPanel")
        c = QHBoxLayout(controls)
        c.setContentsMargins(14, 10, 14, 10)
        c.setSpacing(8)

        toggle = QPushButton("Intercept off")
        toggle.setObjectName("proxyAction")
        toggle.setFixedHeight(34)
        toggle.setCheckable(True)
        toggle.toggled.connect(self.set_proxy_intercept)
        self.proxy_intercept_toggle = toggle
        c.addWidget(toggle)

        forward = QPushButton("Forward")
        forward.setObjectName("proxyAction")
        forward.setFixedHeight(34)
        forward.clicked.connect(self.forward_selected_intercept)
        self.proxy_forward_button = forward
        c.addWidget(forward)

        drop = QPushButton("Drop")
        drop.setObjectName("proxyAction")
        drop.setFixedHeight(34)
        drop.clicked.connect(self.drop_selected_intercept)
        self.proxy_drop_button = drop
        c.addWidget(drop)
        c.addStretch(1)
        layout.addWidget(controls)

        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(6)

        queue_panel = QFrame()
        queue_panel.setObjectName("proxyPanel")
        ql = QVBoxLayout(queue_panel)
        ql.setContentsMargins(12, 10, 12, 10)
        qtitle = QLabel("Intercepted requests — waiting for Forward")
        qtitle.setStyleSheet(f"font-size:13px;font-weight:800;color:{TEXT};")
        ql.addWidget(qtitle)
        table = QTableWidget(0, 4)
        table.setObjectName("proxyTable")
        table.setHorizontalHeaderLabels(["#", "METHOD", "URL", "TYPE"])
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.itemSelectionChanged.connect(self.show_intercept_selection)
        ql.addWidget(table, 1)
        self.proxy_intercept_table = table
        splitter.addWidget(queue_panel)

        editor_panel = QFrame()
        editor_panel.setObjectName("proxyPanel")
        el = QVBoxLayout(editor_panel)
        el.setContentsMargins(12, 10, 12, 10)
        editor_title = QLabel("Request waiting")
        editor_title.setStyleSheet(f"font-size:13px;font-weight:800;color:{TEXT};")
        el.addWidget(editor_title)
        editor = QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        editor.setPlainText("No intercepted request. Turn Intercept on, then browse with the KCONK Chrome window.")
        editor.setObjectName("proxyInspectorText")
        self.proxy_intercept_editor = editor
        el.addWidget(editor, 1)
        splitter.addWidget(editor_panel)
        splitter.setSizes([250, 220])
        layout.addWidget(splitter, 1)
        return page

    def set_proxy_intercept(self, enabled: bool) -> None:
        self.proxy_intercept_enabled = bool(enabled)
        if hasattr(self, "proxy_intercept_toggle"):
            self.proxy_intercept_toggle.setText("Intercept on" if enabled else "Intercept off")
        if hasattr(self, "proxy_intercept_status"):
            self.proxy_intercept_status.setText(
                "Intercept is ON — browser requests will wait for Forward" if enabled
                else "Intercept is off — browser traffic flows normally"
            )
        capture = getattr(self, "chrome_capture", None)
        if capture is not None and capture.isRunning():
            capture.set_intercept(enabled)

    def _format_intercept_request(self, req) -> str:
        lines = [f"{req.method} {req.url} HTTP/1.1"]
        for key, value in req.headers.items():
            lines.append(f"{key}: {value}")
        if req.body:
            lines.extend(["", req.body])
        return "\n".join(lines)

    def on_proxy_intercepted(self, req) -> None:
        if not self._is_in_scope(req.url):
            return
        self.proxy_intercepted[req.paused_request_id] = req
        table = getattr(self, "proxy_intercept_table", None)
        if table is None:
            return
        from PySide6.QtWidgets import QTableWidgetItem
        row = table.rowCount()
        table.insertRow(row)
        values = [str(row + 1), req.method, req.url, req.resource_type]
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            if col == 0:
                item.setData(Qt.UserRole, req.paused_request_id)
            table.setItem(row, col, item)
        table.selectRow(row)
        self.proxy_intercept_selected = req.paused_request_id
        if hasattr(self, "proxy_intercept_editor"):
            self.proxy_intercept_editor.setPlainText(self._format_intercept_request(req))
        self.select_proxy_subtab("INTERCEPT")

    def show_intercept_selection(self) -> None:
        table = getattr(self, "proxy_intercept_table", None)
        if table is None or not table.selectedItems():
            return
        item = table.item(table.currentRow(), 0)
        if item is None:
            return
        paused_id = item.data(Qt.UserRole)
        req = self.proxy_intercepted.get(paused_id)
        if req is None:
            return
        self.proxy_intercept_selected = paused_id
        if hasattr(self, "proxy_intercept_editor"):
            self.proxy_intercept_editor.setPlainText(self._format_intercept_request(req))

    def _remove_intercept_row(self, paused_id: str) -> None:
        table = getattr(self, "proxy_intercept_table", None)
        if table is None:
            return
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item and item.data(Qt.UserRole) == paused_id:
                table.removeRow(row)
                break
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item:
                item.setText(str(row + 1))

    def forward_selected_intercept(self) -> None:
        paused_id = self.proxy_intercept_selected
        req = self.proxy_intercepted.get(paused_id) if paused_id else None
        capture = getattr(self, "chrome_capture", None)
        if req is None or capture is None or not capture.isRunning():
            return
        capture.forward(req.paused_request_id, req.tab_id)
        self.proxy_intercepted.pop(paused_id, None)
        self._remove_intercept_row(paused_id)
        self.proxy_intercept_selected = None
        if hasattr(self, "proxy_intercept_editor"):
            self.proxy_intercept_editor.setPlainText("Request forwarded. Waiting for the browser response…")

    def drop_selected_intercept(self) -> None:
        paused_id = self.proxy_intercept_selected
        req = self.proxy_intercepted.get(paused_id) if paused_id else None
        capture = getattr(self, "chrome_capture", None)
        if req is None or capture is None or not capture.isRunning():
            return
        capture.drop(req.paused_request_id, req.tab_id)
        self.proxy_intercepted.pop(paused_id, None)
        self._remove_intercept_row(paused_id)
        self.proxy_intercept_selected = None
        if hasattr(self, "proxy_intercept_editor"):
            self.proxy_intercept_editor.setPlainText("Request dropped. The browser will receive a blocked response.")

    def build_proxy_history(self) -> QFrame:
        page = QFrame()
        page.setObjectName("proxyWorkspace")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        header = QHBoxLayout()
        title = QLabel("HTTP history")
        title.setStyleSheet(f"font-size:22px;font-weight:800;color:{GOLD_BRIGHT};")
        header.addWidget(title)
        header.addStretch(1)
        filter_label = QLabel("Filter: All traffic")
        filter_label.setStyleSheet(f"font-size:12px;color:{TEXT_DIM};")
        header.addWidget(filter_label)
        layout.addLayout(header)

        table_frame = QFrame()
        table_frame.setObjectName("proxyPanel")
        tf = QVBoxLayout(table_frame)
        tf.setContentsMargins(14, 14, 14, 14)
        table = QTableWidget(0, 7)
        table.setObjectName("proxyTable")
        self.proxy_history_table = table
        table.setHorizontalHeaderLabels(["#", "HOST", "METHOD", "URL", "STATUS", "LENGTH", "MIME TYPE"])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setAlternatingRowColors(False)
        table.itemSelectionChanged.connect(self.show_proxy_history_selection)
        tf.addWidget(table)

        # Both the history area and the request/response inspector are resizable.
        # The lower inspector is a real splitter so the user can drag the divider
        # between Request and Response, matching the reference workflow.
        inspector_splitter = QSplitter(Qt.Horizontal)
        inspector_splitter.setObjectName("proxyInspectorSplitter")
        inspector_splitter.setChildrenCollapsible(False)
        inspector_splitter.setHandleWidth(6)

        for title_text, empty_text in (
            ("Request", "No request selected."),
            ("Response", "No response available."),
        ):
            panel = QFrame()
            panel.setObjectName("proxyPanel")
            pl = QVBoxLayout(panel)
            pl.setContentsMargins(12, 10, 12, 10)
            lab = QLabel(title_text)
            lab.setStyleSheet(f"font-size:14px;font-weight:800;color:{TEXT};")
            body = QPlainTextEdit()
            body.setReadOnly(True)
            body.setPlainText(empty_text)
            body.setObjectName("proxyInspectorText")
            body.setLineWrapMode(QPlainTextEdit.NoWrap)
            if title_text == "Request":
                self.proxy_request_editor = body
            else:
                self.proxy_response_editor = body
            pl.addWidget(lab)
            pl.addWidget(body, 1)
            inspector_splitter.addWidget(panel)

        inspector_splitter.setStretchFactor(0, 1)
        inspector_splitter.setStretchFactor(1, 1)
        inspector_splitter.setSizes([430, 430])

        content_splitter = QSplitter(Qt.Vertical)
        content_splitter.setObjectName("proxyContentSplitter")
        content_splitter.setChildrenCollapsible(False)
        content_splitter.setHandleWidth(6)
        content_splitter.addWidget(table_frame)
        content_splitter.addWidget(inspector_splitter)
        content_splitter.setStretchFactor(0, 3)
        content_splitter.setStretchFactor(1, 2)
        content_splitter.setSizes([330, 250])
        layout.addWidget(content_splitter, 1)
        return page

    def open_chrome_capture(self) -> None:
        """Launch Chrome and capture browser network activity into Proxy history."""
        if self.chrome_capture is not None and self.chrome_capture.isRunning():
            self.pages.setCurrentWidget(self.proxy_page)
            self.select_proxy_subtab("HTTP HISTORY")
            return
        try:
            self.chrome_process, chrome_port, self.chrome_profile = launch_chrome("about:blank")
            self.chrome_capture = ChromeCaptureThread(chrome_port, "")
            self.chrome_capture.transaction.connect(self.on_proxy_transaction)
            self.chrome_capture.intercepted.connect(self.on_proxy_intercepted)
            self.chrome_capture.updated.connect(self.on_proxy_transaction_updated)
            self.chrome_capture.error.connect(self.on_proxy_capture_error)
            self.chrome_capture.state.connect(self.on_proxy_capture_state)
            self.chrome_capture.set_scope(self.proxy_scope)
            self.chrome_capture.start()
            if self.proxy_intercept_enabled:
                # Apply the requested intercept mode as soon as the capture thread
                # has started; newly attached tabs inherit the same state.
                self.chrome_capture.set_intercept(True)
            self.pages.setCurrentWidget(self.proxy_page)
            self.select_proxy_subtab("HTTP HISTORY")
        except Exception as exc:
            self.on_proxy_capture_error(str(exc))

    def on_proxy_capture_state(self, message: str) -> None:
        self.proxy_capture_state = message

    def on_proxy_capture_error(self, message: str) -> None:
        self.proxy_capture_state = f"Capture error: {message}"

    def _is_browser_url(self, url: str) -> bool:
        return bool(url) and (url.startswith("http://") or url.startswith("https://"))

    def on_proxy_transaction(self, record) -> None:
        if not self._is_browser_url(record.url) or not self._is_in_scope(record.url):
            return
        self.proxy_records[record.request_id] = record
        self._insert_proxy_history_row(record)

    def on_proxy_transaction_updated(self, record) -> None:
        if not self._is_browser_url(record.url) or not self._is_in_scope(record.url):
            return
        self.proxy_records[record.request_id] = record
        table = getattr(self, "proxy_history_table", None)
        if table is None:
            return
        for row in range(table.rowCount()):
            if table.item(row, 0) and table.item(row, 0).data(Qt.UserRole) == record.request_id:
                values = [
                    str(row + 1),
                    self._url_host(record.url),
                    record.method,
                    record.url,
                    str(record.status or "—"),
                    str(record.response_size or "—"),
                    record.mime_type or "—",
                ]
                for col, value in enumerate(values):
                    item = table.item(row, col)
                    if item is None:
                        from PySide6.QtWidgets import QTableWidgetItem
                        item = QTableWidgetItem()
                        table.setItem(row, col, item)
                    item.setText(value)
                return

    def _url_host(self, url: str) -> str:
        try:
            return url.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
        except Exception:
            return url

    def _insert_proxy_history_row(self, record) -> None:
        from PySide6.QtWidgets import QTableWidgetItem
        table = getattr(self, "proxy_history_table", None)
        if table is None:
            return
        for row in range(table.rowCount()):
            if table.item(row, 0) and table.item(row, 0).data(Qt.UserRole) == record.request_id:
                return
        row = table.rowCount()
        table.insertRow(row)
        values = [
            str(row + 1), self._url_host(record.url), record.method, record.url,
            str(record.status or "—"), str(record.response_size or "—"), record.mime_type or "—",
        ]
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            if col == 0:
                item.setData(Qt.UserRole, record.request_id)
            table.setItem(row, col, item)
        table.scrollToBottom()

    def show_proxy_history_selection(self) -> None:
        table = getattr(self, "proxy_history_table", None)
        if table is None or not table.selectedItems():
            return
        row = table.currentRow()
        item = table.item(row, 0)
        if item is None:
            return
        record = self.proxy_records.get(item.data(Qt.UserRole))
        if record is None:
            return
        request_lines = [f"{record.method} {record.url} HTTP/1.1"]
        for key, value in record.request_headers.items():
            request_lines.append(f"{key}: {value}")
        if record.request_body:
            request_lines.extend(["", record.request_body])
        response_lines = [f"HTTP/1.1 {record.status} {record.status_text}".rstrip()]
        for key, value in record.response_headers.items():
            response_lines.append(f"{key}: {value}")
        if record.response_body:
            response_lines.extend(["", record.response_body])
        if hasattr(self, "proxy_request_editor"):
            self.proxy_request_editor.setPlainText("\n".join(request_lines))
            self.proxy_response_editor.setPlainText("\n".join(response_lines))

    def select_proxy_subtab(self, name: str) -> None:
        self.proxy_subtab = name
        index = 0 if name == "INTERCEPT" else 1
        self.proxy_content.setCurrentIndex(index)
        for label, button in self.proxy_sub_buttons.items():
            button.setObjectName("proxySubActive" if label == name else "proxySubItem")
            button.style().unpolish(button)
            button.style().polish(button)
            button.update()

    def build_dashboard(self) -> QFrame:
        page = QFrame()
        page.setObjectName("dashboardPage")
        page.setFixedSize(DESIGN_WIDTH, DESIGN_HEIGHT - NAVBAR_HEIGHT)

        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Centered information card, matching the approved dashboard mockup.
        card = QFrame()
        card.setObjectName("projectCard")
        card.setStyleSheet(f"background: {"#ffffff" if BG == "#f2f1eb" else "#081b14"}; border: 1px solid {"#b8b39f" if BG == "#f2f1eb" else "#315944"}; border-radius: 18px;")
        card.setFixedSize(530, 525)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(46, 28, 46, 28)
        card_layout.setSpacing(0)

        title = QLabel("KCONK Suite")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            f"font-size:30px;font-weight:800;color:{GOLD_BRIGHT};"
        )
        card_layout.addWidget(title)

        edition = QLabel("C O M M U N I T Y   E D I T I O N")
        edition.setAlignment(Qt.AlignCenter)
        edition.setStyleSheet(
            f"font-size:12px;font-weight:500;color:{TEXT_DIM};letter-spacing:3px;"
        )
        card_layout.addWidget(edition)
        card_layout.addSpacing(22)

        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)
        pix = QPixmap(str(LOGO))
        if not pix.isNull():
            logo.setPixmap(pix.scaled(235, 235, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setFixedHeight(250)
        card_layout.addWidget(logo)

        divider = QFrame()
        divider.setObjectName("cardDivider")
        divider.setStyleSheet(f"background: {"#c8c1aa" if BG == "#f2f1eb" else "#315944"}; border: 0;")
        divider.setFixedHeight(1)
        card_layout.addWidget(divider)
        card_layout.addSpacing(20)

        info = QGridLayout()
        info.setContentsMargins(0, 0, 0, 0)
        info.setHorizontalSpacing(24)
        info.setVerticalSpacing(18)

        creator_icon = QLabel("♙")
        creator_icon.setStyleSheet(f"font-size:22px;color:{TEXT};")
        creator_label = QLabel("Dibuat oleh")
        creator_label.setStyleSheet(f"font-size:15px;color:{TEXT};")
        creator_value = QLabel("KCONK")
        creator_value.setStyleSheet(f"font-size:16px;font-weight:800;color:{GOLD_BRIGHT};")

        release_icon = QLabel("▣")
        release_icon.setStyleSheet(f"font-size:20px;color:{TEXT};")
        release_label = QLabel("Dirilis pada")
        release_label.setStyleSheet(f"font-size:15px;color:{TEXT};")
        release_value = QLabel("15 September 2025")
        release_value.setStyleSheet(f"font-size:16px;font-weight:800;color:{GOLD_BRIGHT};")

        info.addWidget(creator_icon, 0, 0)
        info.addWidget(creator_label, 0, 1)
        info.addWidget(creator_value, 0, 2)
        info.addWidget(release_icon, 1, 0)
        info.addWidget(release_label, 1, 1)
        info.addWidget(release_value, 1, 2)
        info.setColumnStretch(1, 1)
        card_layout.addLayout(info)

        # Place the card at the center of the fixed dashboard canvas.
        wrapper = QHBoxLayout()
        wrapper.setContentsMargins(0, 0, 0, 0)
        wrapper.addStretch(1)
        wrapper.addWidget(card)
        wrapper.addStretch(1)
        layout.addStretch(1)
        layout.addLayout(wrapper)
        layout.addStretch(1)
        return page

    def closeEvent(self, event) -> None:
        capture = getattr(self, "chrome_capture", None)
        if capture is not None:
            capture.stop()
            if capture.isRunning():
                capture.wait(1500)
        proc = getattr(self, "chrome_process", None)
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
        super().closeEvent(event)

    def build_navbar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("navbar")
        bar.setFixedSize(DESIGN_WIDTH, NAVBAR_HEIGHT)

        # Build the navbar as a fixed content row plus an explicit 1px
        # separator. Using a real child line avoids Qt stylesheet border
        # painting being visually covered by the child widgets.
        outer = QVBoxLayout(bar)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        row = QWidget()
        row.setObjectName("navRow")
        row.setFixedSize(DESIGN_WIDTH, NAVBAR_HEIGHT - 1)
        root = QHBoxLayout(row)
        root.setContentsMargins(18, 0, 18, 0)
        root.setSpacing(0)

        # ---- Brand -------------------------------------------------------
        brand = QWidget()
        brand.setObjectName("navBrand")
        brand.setFixedWidth(220)
        brand_layout = QHBoxLayout(brand)
        brand_layout.setContentsMargins(0, 0, 0, 0)
        brand_layout.setSpacing(9)

        icon = QLabel()
        icon.setFixedSize(36, 36)
        icon.setAlignment(Qt.AlignCenter)
        pix = QPixmap(str(LOGO))
        if not pix.isNull():
            icon.setPixmap(pix.scaled(34, 34, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        brand_layout.addWidget(icon)

        name_col = QVBoxLayout()
        name_col.setContentsMargins(0, 0, 0, 0)
        name_col.setSpacing(0)

        name = QLabel("KCONK Suite")
        name.setStyleSheet(f"font-size:17px;font-weight:800;color:{GOLD_BRIGHT};")
        version = QLabel(f"Community Edition v{__version__}")
        version.setStyleSheet(f"font-size:9px;color:{TEXT_DIM};")
        name_col.addWidget(name)
        name_col.addWidget(version)
        brand_layout.addLayout(name_col)
        root.addWidget(brand)

        # Vertical divider separates brand from module navigation.
        divider = QFrame()
        divider.setObjectName("navDivider")
        divider.setFixedSize(1, 28)
        root.addWidget(divider)
        root.addSpacing(10)

        # ---- Main navigation -------------------------------------------
        # Keep the eight modules in one fixed-width rail. This is easier to
        # reason about than relying on layout compression/stretching.
        nav_rail = NavRail(self.NAV_ITEMS, self.select_nav, self.nav_order_changed, row)
        self.nav_buttons = nav_rail.buttons
        self.nav_rail = nav_rail
        root.addWidget(nav_rail)
        root.addStretch(1)

        # ---- Utilities --------------------------------------------------
        web_btn = QPushButton("🌐")
        web_btn.setObjectName("navUtility")
        web_btn.setFixedSize(34, 34)
        web_btn.setToolTip("Open Chrome and capture HTTP history")
        web_btn.clicked.connect(self.open_chrome_capture)
        root.addWidget(web_btn)
        root.addSpacing(4)

        light_btn = QPushButton("☀")
        light_btn.setObjectName("navUtility")
        light_btn.setFixedSize(34, 34)
        light_btn.setToolTip("Light mode")
        light_btn.clicked.connect(lambda: self.set_theme("light"))
        root.addWidget(light_btn)
        root.addSpacing(4)

        dark_btn = QPushButton("☾")
        dark_btn.setObjectName("navUtility")
        dark_btn.setFixedSize(34, 34)
        dark_btn.setToolTip("Dark mode")
        dark_btn.clicked.connect(lambda: self.set_theme("dark"))
        root.addWidget(dark_btn)
        root.addSpacing(4)

        settings_btn = QPushButton("⚙")
        settings_btn.setObjectName("navUtility")
        settings_btn.setFixedSize(34, 34)
        settings_btn.setToolTip("Settings")
        settings_btn.clicked.connect(self.open_settings_window)
        root.addWidget(settings_btn)
        root.addSpacing(4)

        outer.addWidget(row)

        bottom_line = QFrame()
        bottom_line.setObjectName("navBottomLine")
        bottom_line.setFixedSize(DESIGN_WIDTH, 1)
        outer.addWidget(bottom_line)

        return bar

    def set_theme(self, theme: str) -> None:
        """Switch theme without breaking the stacked page geometry."""
        global BG, NAV_BG, NAV_BG_ACTIVE, LINE, LINE_HOVER, TEXT, TEXT_DIM, GOLD, GOLD_BRIGHT, GREEN, STYLE
        if theme == "light":
            BG = "#f2f1eb"
            NAV_BG = "#ffffff"
            NAV_BG_ACTIVE = "#eee8d5"
            LINE = "#c8c1aa"
            LINE_HOVER = "#a69d83"
            TEXT = "#20231f"
            TEXT_DIM = "#687067"
            GOLD = "#9a7425"
            GOLD_BRIGHT = "#b88628"
            GREEN = "#52715e"
            card_bg, card_line, table_bg = "#ffffff", "#b8b39f", "#fbfaf5"
        else:
            BG = "#06110d"
            NAV_BG = "#07130f"
            NAV_BG_ACTIVE = "#0d2118"
            LINE = "#284437"
            LINE_HOVER = "#3e5f4d"
            TEXT = "#eee5cc"
            TEXT_DIM = "#9da69b"
            GOLD = "#d8b56a"
            GOLD_BRIGHT = "#f0d18b"
            GREEN = "#7fa888"
            card_bg, card_line, table_bg = "#081b14", "#315944", "#06110d"

        # Rebuild the stylesheet from the current palette. Do not hard-code dark
        # surfaces into the light theme: every major surface follows the theme.
        STYLE = f"""
QMainWindow, QWidget {{ background: {BG}; color: {TEXT}; font-family: 'DejaVu Sans'; }}
QLabel {{ background: transparent; color: {TEXT}; }}
QScrollArea {{ border: 0; background: {BG}; }}
QScrollBar:vertical {{ width: 11px; background: {BG}; }}
QScrollBar::handle:vertical {{ background: {LINE}; border-radius: 5px; min-height: 45px; }}
QScrollBar:horizontal {{ height: 11px; background: {BG}; }}
QScrollBar::handle:horizontal {{ background: {LINE}; border-radius: 5px; min-width: 45px; }}
QFrame#navbar, QWidget#navRow, QFrame#proxySubbar {{ background: {NAV_BG}; border: 0; }}
QFrame#navBottomLine, QFrame#navDivider, QFrame#proxySubLine {{ background: {LINE}; border: 0; }}
QWidget#navBrand, QWidget#navRail {{ background: transparent; }}
QFrame#dashboardPage, QFrame#proxyPage, QFrame#proxyWorkspace, QFrame#proxyContent {{ background: {BG}; border: 0; }}
QFrame#projectCard, QFrame#proxyPanel {{ background: {card_bg}; border: 1px solid {card_line}; border-radius: 10px; }}
QFrame#cardDivider {{ background: {LINE}; border: 0; }}
QLineEdit#proxyScopeEdit {{ background: {table_bg}; color: {TEXT}; border: 1px solid {LINE}; border-radius: 7px; padding: 0 10px; }}
QPushButton#navItem, QPushButton#navItemActive {{ background: transparent; border: 0; border-bottom: 2px solid transparent; color: {TEXT_DIM}; padding: 0 4px; font-size: 11px; font-weight: 700; }}
QPushButton#navItem:hover {{ background: {NAV_BG_ACTIVE}; color: {TEXT}; }}
QPushButton#navItemActive {{ background: {NAV_BG_ACTIVE}; border-bottom-color: {GOLD_BRIGHT}; color: {GOLD_BRIGHT}; font-weight: 800; }}
QPushButton#navUtility {{ background: transparent; border: 0; color: {GOLD}; font-size: 16px; }}
QPushButton#navUtility:hover {{ background: {NAV_BG_ACTIVE}; color: {GOLD_BRIGHT}; }}
QPushButton#proxySubItem, QPushButton#proxySubActive {{ background: transparent; border: 0; border-bottom: 2px solid transparent; color: {TEXT_DIM}; padding: 0 14px; font-size: 11px; font-weight: 700; }}
QPushButton#proxySubItem:hover {{ background: {NAV_BG_ACTIVE}; color: {TEXT}; }}
QPushButton#proxySubActive {{ color: {GOLD_BRIGHT}; border-bottom-color: {GOLD_BRIGHT}; background: {NAV_BG_ACTIVE}; }}
QPushButton#proxyAction {{ background: {NAV_BG}; color: {TEXT}; border: 1px solid {LINE}; border-radius: 7px; padding: 0 14px; }}
QPushButton#proxyAction:hover {{ background: {NAV_BG_ACTIVE}; color: {GOLD_BRIGHT}; border-color: {GOLD}; }}
QLineEdit#proxyScopeEdit {{ background: {table_bg}; color: {TEXT}; border: 1px solid {LINE}; border-radius: 7px; padding: 0 10px; }}
QLineEdit#proxyScopeEdit:focus {{ border-color: {GOLD}; }}
QTableWidget#proxyTable {{ background: {table_bg}; color: {TEXT}; border: 0; gridline-color: {LINE}; selection-background-color: {NAV_BG_ACTIVE}; }}
QTableWidget#proxyTable QHeaderView::section {{ background: {NAV_BG_ACTIVE}; color: {TEXT_DIM}; border: 0; padding: 7px; font-size: 10px; font-weight: 700; }}
QPlainTextEdit {{ background: {table_bg}; color: {TEXT}; border: 1px solid {LINE}; }}
"""
        self.setStyleSheet(STYLE)

        # Replace the Dashboard inside QStackedWidget, not in the root layout.
        # The previous implementation accidentally inserted it beside the stack,
        # which is why switching to Light could scramble the whole UI.
        if hasattr(self, "pages") and hasattr(self, "dashboard_page"):
            index = self.pages.indexOf(self.dashboard_page)
            current_page = self.pages.currentWidget()
            if index >= 0:
                old_page = self.dashboard_page
                self.pages.removeWidget(old_page)
                old_page.deleteLater()
                self.dashboard_page = self.build_dashboard()
                self.pages.insertWidget(index, self.dashboard_page)
                # Preserve whichever primary module was open before the theme change.
                if current_page is self.proxy_page:
                    self.pages.setCurrentWidget(self.proxy_page)
                else:
                    self.pages.setCurrentWidget(self.dashboard_page)
        self.refresh_nav_state()

    def open_settings_window(self) -> None:
        """Open Settings as a dedicated child window."""
        if getattr(self, "settings_window", None) is not None and self.settings_window.isVisible():
            self.settings_window.raise_()
            self.settings_window.activateWindow()
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("KCONK Suite — Settings")
        dialog.setObjectName("settingsWindow")
        dialog.setFixedSize(620, 470)
        dialog.setModal(False)
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        self.settings_window = dialog

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        heading = QLabel("Settings")
        heading.setStyleSheet(f"font-size:24px;font-weight:800;color:{GOLD_BRIGHT};")
        layout.addWidget(heading)

        subtitle = QLabel("Configure the KCONK Suite interface and workspace.")
        subtitle.setStyleSheet(f"font-size:12px;color:{TEXT_DIM};")
        layout.addWidget(subtitle)

        appearance = QFrame()
        appearance.setObjectName("settingsSection")
        appearance_layout = QGridLayout(appearance)
        appearance_layout.setContentsMargins(18, 16, 18, 16)
        appearance_layout.setHorizontalSpacing(18)
        appearance_layout.setVerticalSpacing(14)

        section_title = QLabel("Appearance")
        section_title.setStyleSheet(f"font-size:15px;font-weight:800;color:{TEXT};")
        appearance_layout.addWidget(section_title, 0, 0, 1, 2)

        theme_label = QLabel("Theme")
        theme_label.setStyleSheet(f"color:{TEXT};font-size:13px;")

        # Use a styled QMenu instead of the platform QComboBox popup.
        # The native popup frame can add compositor/desktop-specific white
        # strips above and below the list even when the application is dark.
        theme_button = QPushButton("Dark  ▾")
        theme_button.setFixedHeight(36)
        theme_button.setStyleSheet(f"""
            QPushButton {{
                background: {NAV_BG};
                color: {TEXT};
                border: 1px solid {LINE};
                border-radius: 8px;
                text-align: left;
                padding: 0 12px;
                font-size: 13px;
            }}
            QPushButton:hover {{
                border-color: {GOLD};
                color: {GOLD_BRIGHT};
            }}
        """)

        theme_menu = QMenu(theme_button)
        theme_menu.setWindowFlag(Qt.FramelessWindowHint, True)
        theme_menu.setAttribute(Qt.WA_TranslucentBackground, False)

        def refresh_theme_menu():
            menu_bg = NAV_BG
            menu_fg = TEXT
            menu_hover = NAV_BG_ACTIVE
            menu_style = f"""
                QMenu {{
                    background: {menu_bg};
                    color: {menu_fg};
                    border: 1px solid {LINE};
                    padding: 4px;
                }}
                QMenu::item {{
                    background: transparent;
                    color: {menu_fg};
                    padding: 8px 18px;
                    min-width: 100px;
                    border-radius: 5px;
                }}
                QMenu::item:selected {{
                    background: {menu_hover};
                    color: {GOLD_BRIGHT};
                }}
            """
            theme_menu.setStyleSheet(menu_style)
            theme_button.setText(("Light" if BG == "#f2f1eb" else "Dark") + "  ▾")

        dark_action = QAction("Dark", theme_menu)
        light_action = QAction("Light", theme_menu)
        dark_action.triggered.connect(lambda: (self.set_theme("dark"), refresh_theme_menu()))
        light_action.triggered.connect(lambda: (self.set_theme("light"), refresh_theme_menu()))
        theme_menu.addAction(dark_action)
        theme_menu.addAction(light_action)
        refresh_theme_menu()
        theme_button.clicked.connect(lambda: theme_menu.exec(theme_button.mapToGlobal(QPoint(0, theme_button.height()))))

        appearance_layout.addWidget(theme_label, 1, 0)
        appearance_layout.addWidget(theme_button, 1, 1)

        nav_label = QLabel("Navigation order")
        nav_label.setStyleSheet(f"color:{TEXT};font-size:13px;")
        nav_value = QLabel("Drag navbar items directly to reorder them.")
        nav_value.setWordWrap(True)
        nav_value.setStyleSheet(f"color:{TEXT_DIM};font-size:12px;")
        appearance_layout.addWidget(nav_label, 2, 0)
        appearance_layout.addWidget(nav_value, 2, 1)

        reset_nav = QPushButton("Reset navigation order")
        reset_nav.clicked.connect(self.reset_nav_order)
        appearance_layout.addWidget(reset_nav, 3, 1, Qt.AlignRight)

        layout.addWidget(appearance)

        about = QFrame()
        about.setObjectName("settingsSection")
        about_layout = QVBoxLayout(about)
        about_layout.setContentsMargins(18, 16, 18, 16)
        about_title = QLabel("About KCONK Suite")
        about_title.setStyleSheet(f"font-size:15px;font-weight:800;color:{TEXT};")
        about_layout.addWidget(about_title)
        about_text = QLabel(f"Community Edition v{__version__}\nCreated by KCONK · Released 15 September 2025")
        about_text.setStyleSheet(f"font-size:12px;color:{TEXT_DIM};line-height:1.4;")
        about_layout.addWidget(about_text)
        layout.addWidget(about)

        layout.addStretch(1)

        close_btn = QPushButton("Close")
        close_btn.setFixedSize(100, 34)
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn, 0, Qt.AlignRight)

        dialog.setStyleSheet(f"""
            QDialog#settingsWindow {{ background: {BG}; color: {TEXT}; }}
            QDialog#settingsWindow QLabel {{ background: transparent; }}
            QFrame#settingsSection {{ background: {NAV_BG_ACTIVE}; border: 1px solid {LINE}; border-radius: 12px; }}
            QComboBox {{
                background: {NAV_BG};
                color: {TEXT};
                border: 1px solid {LINE};
                border-radius: 7px;
                padding: 7px 10px;
                min-width: 150px;
                selection-background-color: {NAV_BG_ACTIVE};
                selection-color: {TEXT};
            }}
            QComboBox::drop-down {{
                border: 0;
                width: 26px;
            }}
            QComboBox::down-arrow {{
                width: 9px;
                height: 9px;
            }}
            QComboBox QAbstractItemView {{
                background: {NAV_BG};
                color: {TEXT};
                border: 0;
                outline: 0;
                padding: 0;
                margin: 0;
                selection-background-color: {NAV_BG_ACTIVE};
                selection-color: {TEXT};
            }}
            QComboBox QAbstractItemView::item {{
                background: {NAV_BG};
                color: {TEXT};
                border: 0;
                padding: 7px 8px;
                min-height: 22px;
            }}
            QComboBox QAbstractItemView::item:hover {{
                background: {NAV_BG_ACTIVE};
                color: {GOLD_BRIGHT};
            }}
            QComboBox QScrollBar:vertical {{
                width: 8px;
                background: {NAV_BG};
                margin: 0;
            }}
            QComboBox QScrollBar::handle:vertical {{
                background: {LINE_HOVER};
                border-radius: 4px;
                min-height: 20px;
            }}
            QComboBox QScrollBar::add-line:vertical,
            QComboBox QScrollBar::sub-line:vertical {{
                height: 0;
                background: transparent;
            }}
            QPushButton {{ background: {NAV_BG}; color: {TEXT}; border: 1px solid {LINE}; border-radius: 7px; padding: 7px 12px; }}
            QPushButton:hover {{ background: {NAV_BG_ACTIVE}; color: {GOLD_BRIGHT}; border-color: {GOLD}; }}
        """)
        dialog.finished.connect(lambda _result: setattr(self, "settings_window", None))
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def reset_nav_order(self) -> None:
        """Restore the default eight-item navbar order."""
        default_order = [name for name, _width in self.NAV_ITEMS]
        if hasattr(self, "nav_rail"):
            self.nav_rail.set_order(default_order)
            self.refresh_nav_state()

    def nav_order_changed(self, order) -> None:
        """Keep the active state intact after a drag reorder."""
        self.nav_buttons = self.nav_rail.buttons
        self.refresh_nav_state()

    def select_nav(self, name: str) -> None:
        self.active_nav = name
        if hasattr(self, "pages"):
            if name == "DASHBOARD":
                self.pages.setCurrentWidget(self.dashboard_page)
            elif name == "PROXY":
                self.pages.setCurrentWidget(self.proxy_page)
            else:
                # Other modules remain intentionally blank while their UI is
                # built one module at a time.
                self.pages.setCurrentWidget(self.blank_module_page(name))
        self.refresh_nav_state()

    def blank_module_page(self, name: str) -> QFrame:
        if not hasattr(self, "_blank_pages"):
            self._blank_pages = {}
        if name not in self._blank_pages:
            page = QFrame()
            page.setObjectName("blankPage")
            label = QLabel(name)
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet(f"font-size:18px;font-weight:700;color:{TEXT_DIM};")
            l = QVBoxLayout(page)
            l.addWidget(label)
            page.setFixedSize(DESIGN_WIDTH, DESIGN_HEIGHT - NAVBAR_HEIGHT)
            self.pages.addWidget(page)
            self._blank_pages[name] = page
        return self._blank_pages[name]

    def refresh_nav_state(self) -> None:
        for name, button in self.nav_buttons.items():
            button.setObjectName("navItemActive" if name == self.active_nav else "navItem")
            button.style().unpolish(button)
            button.style().polish(button)
            button.update()

