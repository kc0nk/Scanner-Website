from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)


ROOT = Path(__file__).resolve().parents[1]
LOGO = ROOT / "assets" / "kconk_logo.png"

# -----------------------------------------------------------------------------
# Fixed design canvas
# -----------------------------------------------------------------------------
# The desktop window itself can be resized freely, but the UI is rendered on a
# fixed design canvas. A viewport/scrollbar handles smaller displays instead of
# changing the spacing, proportions, typography, or card geometry.
DESIGN_WIDTH = 1500
DESIGN_HEIGHT = 920
TOPBAR_HEIGHT = 78
STATUSBAR_HEIGHT = 42
BODY_HEIGHT = DESIGN_HEIGHT - TOPBAR_HEIGHT - STATUSBAR_HEIGHT
SIDEBAR_WIDTH = 330
CONTENT_WIDTH = DESIGN_WIDTH - SIDEBAR_WIDTH

BG = "#06110d"
BG_2 = "#081912"
PANEL = "#0b2118"
PANEL_2 = "#0a1a14"
LINE = "#284437"
LINE_SOFT = "#1d352b"
TEXT = "#eee4c8"
TEXT_2 = "#b8b79f"
MUTED = "#7f8e82"
GOLD = "#d8b56a"
GOLD_2 = "#f1d38c"
GREEN = "#6d9f74"
GREEN_BRIGHT = "#8fb991"

STYLE = f"""
QMainWindow, QWidget {{
    background: {BG};
    color: {TEXT};
    font-family: "DejaVu Sans";
}}

QScrollArea#viewport {{
    background: {BG};
    border: 0;
}}

QScrollBar:vertical {{
    width: 11px;
    background: #07140f;
    border-left: 1px solid {LINE};
}}
QScrollBar::handle:vertical {{
    background: #294938;
    border-radius: 5px;
    min-height: 42px;
}}
QScrollBar::handle:vertical:hover {{ background: #3a624c; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}

QScrollBar:horizontal {{
    height: 11px;
    background: #07140f;
    border-top: 1px solid {LINE};
}}
QScrollBar::handle:horizontal {{
    background: #294938;
    border-radius: 5px;
    min-width: 42px;
}}
QScrollBar::handle:horizontal:hover {{ background: #3a624c; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

QFrame#topbar {{
    background: #07140f;
    border-bottom: 1px solid {LINE};
}}

QFrame#sidebar {{
    background: #06140f;
    border-right: 1px solid {LINE};
}}

QFrame#content {{
    background: {BG};
}}

QFrame#card {{
    background: {PANEL};
    border: 1px solid {LINE};
    border-radius: 12px;
}}

QFrame#subcard {{
    background: {PANEL_2};
    border: 1px solid {LINE_SOFT};
    border-radius: 10px;
}}

QFrame#logoPane {{
    background: qradialgradient(cx:0.50, cy:0.44, radius:0.72,
        stop:0 #173c2a, stop:0.46 #0c2419, stop:1 #06130e);
    border: 1px solid {LINE};
    border-radius: 14px;
}}

QLabel {{ background: transparent; }}

QLineEdit {{
    background: #061710;
    border: 1px solid {LINE};
    border-radius: 8px;
    padding: 9px 12px;
    color: {TEXT};
    selection-background-color: #335944;
}}

QPushButton {{
    background: #0d261b;
    border: 1px solid {LINE};
    border-radius: 8px;
    padding: 8px 14px;
    color: {TEXT};
    font-weight: 700;
}}

QPushButton:hover {{
    background: #173625;
    border-color: {GOLD};
}}

QPushButton#primary {{
    background: #c7a45f;
    color: #142017;
    border-color: #e0bf79;
}}

QPushButton#primary:hover {{ background: {GOLD_2}; }}

QPushButton#nav {{
    text-align: left;
    background: transparent;
    border: 1px solid transparent;
    padding: 9px 11px;
    color: {TEXT_2};
    font-weight: 600;
}}

QPushButton#nav:hover {{
    background: #102a1e;
    color: {TEXT};
}}

QPushButton#navActive {{
    text-align: left;
    background: #173528;
    border: 1px solid #3a5b48;
    padding: 9px 11px;
    color: {GOLD_2};
    font-weight: 800;
}}
"""


def text_label(text: str, size: int = 13, color: str = TEXT, bold: bool = False) -> QLabel:
    label = QLabel(text)
    weight = 700 if bold else 400
    label.setStyleSheet(f"font-size:{size}px; color:{color}; font-weight:{weight};")
    return label


def section_title(text: str) -> QLabel:
    return text_label(text, 15, GOLD_2, True)


def fixed_spacer(width: int) -> QSpacerItem:
    return QSpacerItem(width, 1, QSizePolicy.Fixed, QSizePolicy.Minimum)


class MainWindow(QMainWindow):
    """KCONK UI shell with a fixed visual canvas and viewport-based resizing."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("KCONK Suite — Community Edition v1.0")
        self.resize(1280, 800)
        self.setMinimumSize(760, 520)
        self.setStyleSheet(STYLE)

        self.viewport = QScrollArea()
        self.viewport.setObjectName("viewport")
        self.viewport.setWidgetResizable(False)
        self.viewport.setAlignment(Qt.AlignCenter)
        self.viewport.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.viewport.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setCentralWidget(self.viewport)

        self.canvas = self.build_canvas()
        self.canvas.setFixedSize(DESIGN_WIDTH, DESIGN_HEIGHT)
        self.viewport.setWidget(self.canvas)

    # ------------------------------------------------------------------
    # Fixed canvas: never stretches/reflows with the host desktop size.
    # ------------------------------------------------------------------
    def build_canvas(self) -> QWidget:
        canvas = QWidget()
        canvas.setObjectName("canvas")
        canvas.setFixedSize(DESIGN_WIDTH, DESIGN_HEIGHT)

        outer = QVBoxLayout(canvas)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self.build_topbar())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self.build_sidebar())
        body.addWidget(self.build_content())
        outer.addLayout(body)

        outer.addWidget(self.build_statusbar())
        return canvas

    def build_topbar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("topbar")
        bar.setFixedSize(DESIGN_WIDTH, TOPBAR_HEIGHT)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 10, 18, 10)
        layout.setSpacing(10)

        mark = QLabel()
        pix = QPixmap(str(LOGO))
        if not pix.isNull():
            mark.setPixmap(pix.scaled(46, 46, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        mark.setFixedSize(46, 46)
        layout.addWidget(mark)

        brand = QVBoxLayout()
        brand.setSpacing(1)
        brand.addWidget(text_label("KCONK Suite", 21, GOLD_2, True))
        brand.addWidget(text_label("Community Edition v1.0", 11, TEXT_2))
        brand_widget = QWidget()
        brand_widget.setFixedWidth(214)
        brand_widget.setLayout(brand)
        layout.addWidget(brand_widget)
        layout.addItem(fixed_spacer(8))

        nav_items = [
            "DASHBOARD", "TARGET", "PROXY", "INTRUDER", "REPEATER", "COLLABORATOR",
            "SEQUENCER", "DECODER", "COMPARER", "LOGGER", "ORGANIZER", "EXTENSIONS", "DISCOVER",
        ]
        widths = [82, 63, 60, 75, 78, 103, 84, 78, 77, 65, 84, 89, 76]

        for i, (item, width) in enumerate(zip(nav_items, widths)):
            btn = QPushButton(item)
            btn.setFlat(True)
            btn.setFixedWidth(width)
            active = i == 0
            btn.setStyleSheet(
                f"QPushButton{{border:0;border-bottom:2px solid {'#d2b56d' if active else 'transparent'};"
                f"border-radius:0;padding:15px 3px 13px;color:{'#f0d68f' if active else '#a3aa9e'};"
                f"font-size:10px;font-weight:800;}}QPushButton:hover{{color:{TEXT};}}"
            )
            layout.addWidget(btn)

        layout.addItem(QSpacerItem(1, 1, QSizePolicy.Expanding, QSizePolicy.Minimum))
        for icon in ("◍", "☾", "⚙"):
            b = QPushButton(icon)
            b.setFixedSize(36, 36)
            b.setStyleSheet(
                f"QPushButton{{border:0;color:{GOLD_2};font-size:17px;background:transparent;}}"
                f"QPushButton:hover{{background:#102519;border-radius:8px;}}"
            )
            layout.addWidget(b)
        return bar

    def build_sidebar(self) -> QFrame:
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedSize(SIDEBAR_WIDTH, BODY_HEIGHT)

        layout = QVBoxLayout(side)
        layout.setContentsMargins(18, 18, 18, 14)
        layout.setSpacing(12)

        row = QHBoxLayout()
        row.addWidget(text_label("Tasks", 20, TEXT, True))
        row.addItem(QSpacerItem(1, 1, QSizePolicy.Expanding, QSizePolicy.Minimum))
        for label in ("◫", "⚙", "?"):
            b = QPushButton(label)
            b.setFixedSize(32, 32)
            b.setStyleSheet(
                f"QPushButton{{background:transparent;border:0;color:{TEXT_2};font-size:16px;}}"
                f"QPushButton:hover{{color:{GOLD_2};}}"
            )
            row.addWidget(b)
        layout.addLayout(row)

        action_row = QHBoxLayout()
        action_row.setSpacing(8)
        for label, primary, width in (("New scan", False, 116), ("New live task", True, 132)):
            b = QPushButton(label)
            if primary:
                b.setObjectName("primary")
            b.setFixedWidth(width)
            action_row.addWidget(b)
        action_row.addStretch(1)
        layout.addLayout(action_row)

        search = QLineEdit()
        search.setPlaceholderText("Search")
        search.setFixedSize(294, 38)
        layout.addWidget(search, 0, Qt.AlignLeft)

        nav = QVBoxLayout()
        nav.setSpacing(5)
        task_items = [
            ("◈", "Live passive crawl from Proxy (all traffic)"),
            ("◌", "Site map overview"),
            ("◇", "Target configuration"),
        ]
        for i, (glyph, title) in enumerate(task_items):
            box = QPushButton(f"  {glyph}   {title}")
            box.setObjectName("navActive" if i == 0 else "nav")
            box.setMinimumHeight(44)
            box.setFixedWidth(294)
            nav.addWidget(box)
        layout.addLayout(nav)
        layout.addSpacing(4)

        logo_card = QFrame()
        logo_card.setObjectName("logoPane")
        logo_card.setFixedWidth(294)
        logo_layout = QVBoxLayout(logo_card)
        logo_layout.setContentsMargins(18, 18, 18, 16)
        logo_layout.setSpacing(6)

        logo_view = QLabel()
        logo_view.setAlignment(Qt.AlignCenter)
        pix = QPixmap(str(LOGO))
        if not pix.isNull():
            logo_view.setPixmap(pix.scaled(235, 235, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo_layout.addWidget(logo_view, 1)
        logo_layout.addWidget(text_label("No tasks yet", 18, GOLD_2, True), 0, Qt.AlignHCenter)
        logo_layout.addWidget(text_label("Create a new task to get started.", 11, TEXT_2), 0, Qt.AlignHCenter)
        tagline = text_label("SECURITY THROUGH CURIOSITY", 9, GOLD)
        tagline.setStyleSheet(f"font-size:9px;color:{GOLD};letter-spacing:3px;")
        logo_layout.addSpacing(12)
        logo_layout.addWidget(tagline, 0, Qt.AlignHCenter)
        layout.addWidget(logo_card, 1)

        return side

    def build_content(self) -> QFrame:
        wrapper = QFrame()
        wrapper.setObjectName("content")
        wrapper.setFixedSize(CONTENT_WIDTH, BODY_HEIGHT)

        outer = QVBoxLayout(wrapper)
        outer.setContentsMargins(22, 18, 20, 14)
        outer.setSpacing(12)

        header = QHBoxLayout()
        header.addWidget(text_label("◇", 24, GOLD_2, True))
        title_box = QVBoxLayout()
        title_box.setSpacing(1)
        title_box.addWidget(text_label("1. Live passive crawl from Proxy (all traffic)", 22, TEXT, True))
        title_box.addWidget(text_label("UI preview / scanner shell", 11, MUTED))
        title_widget = QWidget()
        title_widget.setFixedWidth(690)
        title_widget.setLayout(title_box)
        header.addWidget(title_widget)
        header.addItem(QSpacerItem(1, 1, QSizePolicy.Expanding, QSizePolicy.Minimum))
        header.addWidget(text_label("K C O N K", 18, GOLD_2, True))
        outer.addLayout(header)

        tab_row = QHBoxLayout()
        tab_row.addWidget(text_label("Summary", 12, GOLD_2, True))
        tab_row.addItem(QSpacerItem(1, 1, QSizePolicy.Expanding, QSizePolicy.Minimum))
        outer.addLayout(tab_row)

        divider = QFrame()
        divider.setFixedSize(1128, 2)
        divider.setStyleSheet(f"background:{GOLD};")
        outer.addWidget(divider)

        columns = QHBoxLayout()
        columns.setSpacing(14)
        columns.setContentsMargins(0, 0, 0, 0)

        left = QVBoxLayout()
        left.setSpacing(14)
        left.addWidget(self.build_site_map_card())

        right = QVBoxLayout()
        right.setSpacing(14)
        right.addWidget(self.build_config_card())
        right.addWidget(self.build_progress_card())
        right.addWidget(self.build_log_card())

        left_widget = QWidget()
        left_widget.setFixedWidth(560)
        left_widget.setLayout(left)

        right_widget = QWidget()
        right_widget.setFixedWidth(560)
        right_widget.setLayout(right)

        columns.addWidget(left_widget)
        columns.addWidget(right_widget)
        outer.addLayout(columns)
        outer.addStretch(1)
        return wrapper

    def build_site_map_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        card.setFixedSize(560, 644)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 18)
        layout.setSpacing(12)

        head = QHBoxLayout()
        head.addWidget(text_label("▱", 18, GOLD_2, True))
        head.addWidget(section_title("Items added to site map"))
        head.addItem(QSpacerItem(1, 1, QSizePolicy.Expanding, QSizePolicy.Minimum))
        head.addWidget(text_label("View site map", 11, GOLD_2, True))
        layout.addLayout(head)

        shell = QFrame()
        shell.setObjectName("subcard")
        shell.setFixedSize(524, 588)
        shell_layout = QVBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)

        header = QFrame()
        header.setFixedSize(522, 38)
        header.setStyleSheet(
            f"background:#0c2419;border-bottom:1px solid {LINE};"
            "border-top-left-radius:8px;border-top-right-radius:8px;"
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(10, 0, 10, 0)
        header_layout.setSpacing(0)
        for title, stretch in (("Host", 1), ("Method", 1), ("URL", 2), ("Status", 1), ("MIME type", 1)):
            label = text_label(title, 10, "#9aa89d", True)
            label.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            header_layout.addWidget(label, stretch)
        shell_layout.addWidget(header)

        empty = QWidget()
        empty_layout = QVBoxLayout(empty)
        empty_layout.setAlignment(Qt.AlignCenter)
        empty_layout.setContentsMargins(20, 40, 20, 40)
        empty_layout.addStretch(1)
        icon = text_label("⌂", 48, "#5d7064", True)
        icon.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(icon)
        e1 = text_label("No items to show", 17, TEXT, True)
        e1.setAlignment(Qt.AlignCenter)
        e2 = text_label("Items found in the crawl will display here.", 11, TEXT_2)
        e2.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(e1)
        empty_layout.addWidget(e2)
        empty_layout.addStretch(1)
        shell_layout.addWidget(empty, 1)
        layout.addWidget(shell)
        return card

    def build_config_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        card.setFixedSize(560, 228)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)
        head = QHBoxLayout()
        head.addWidget(text_label("◇", 18, GOLD_2, True))
        head.addWidget(section_title("Task configuration"))
        head.addItem(QSpacerItem(1, 1, QSizePolicy.Expanding, QSizePolicy.Minimum))
        head.addWidget(text_label("View configuration", 11, GOLD_2, True))
        layout.addLayout(head)

        rows = [
            ("Task type:", "Live passive crawl"),
            ("Scope:", "Proxy (all traffic)"),
            ("Configuration:", "Add links. Add item itself, same domain and URLs in suite scope."),
        ]
        for k, v in rows:
            r = QHBoxLayout()
            r.setSpacing(16)
            r.addWidget(text_label(k, 12, TEXT, True), 0)
            r.addWidget(text_label(v, 12, TEXT_2), 1)
            layout.addLayout(r)

        r = QHBoxLayout()
        r.addWidget(text_label("Capturing:", 12, TEXT, True))
        r.addStretch(1)
        toggle = QLabel("●")
        toggle.setAlignment(Qt.AlignCenter)
        toggle.setFixedSize(52, 28)
        toggle.setStyleSheet(f"background:{GOLD};color:#18301f;border-radius:14px;font-size:15px;")
        r.addWidget(toggle)
        layout.addLayout(r)
        return card

    def build_progress_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        card.setFixedSize(560, 160)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)
        head = QHBoxLayout()
        head.addWidget(text_label("◷", 18, GOLD_2, True))
        head.addWidget(section_title("Task progress"))
        head.addStretch(1)
        layout.addLayout(head)
        for key, value in (("Site map items added:", "0"), ("Responses processed:", "0"), ("Responses queued:", "0")):
            row = QHBoxLayout()
            row.addWidget(text_label(key, 12, TEXT_2))
            row.addStretch(1)
            row.addWidget(text_label(value, 12, TEXT, True))
            layout.addLayout(row)
        return card

    def build_log_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        card.setFixedSize(560, 242)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)
        head = QHBoxLayout()
        head.addWidget(text_label("▤", 18, GOLD_2, True))
        head.addWidget(section_title("Task log"))
        head.addStretch(1)
        layout.addLayout(head)

        body = QFrame()
        body.setObjectName("subcard")
        body.setFixedSize(524, 174)
        body_l = QVBoxLayout(body)
        body_l.setAlignment(Qt.AlignCenter)
        body_l.addWidget(text_label("No log entries yet", 12, TEXT_2), 0, Qt.AlignCenter)
        line = QFrame()
        line.setFixedSize(30, 2)
        line.setStyleSheet(f"background:{GOLD};")
        body_l.addWidget(line, 0, Qt.AlignHCenter)
        layout.addWidget(body)
        return card

    def build_statusbar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("topbar")
        bar.setFixedSize(DESIGN_WIDTH, STATUSBAR_HEIGHT)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 5, 16, 5)
        layout.addWidget(text_label("◉", 12, GOLD_2, True))
        layout.addWidget(text_label("Event log", 11, TEXT_2, True))
        layout.addSpacing(18)
        layout.addWidget(text_label("All issues", 11, TEXT_2))
        layout.addItem(QSpacerItem(10, 1, QSizePolicy.Expanding, QSizePolicy.Minimum))
        layout.addWidget(text_label("ⓘ", 12, TEXT_2, True))
        layout.addSpacing(8)
        layout.addWidget(text_label("Memory: 0.00MB / 0.00GB", 11, TEXT_2))
        meter = QFrame()
        meter.setFixedSize(78, 10)
        meter.setStyleSheet("background:#203a2c;border-radius:5px;")
        layout.addWidget(meter)
        disabled = QPushButton("Disabled  ▾")
        disabled.setFixedHeight(30)
        disabled.setStyleSheet(
            f"QPushButton{{background:#10251b;border:1px solid {LINE};color:{TEXT_2};"
            "border-radius:7px;padding:0 11px;}"
        )
        layout.addWidget(disabled)
        return bar


if __name__ == "__main__":
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
