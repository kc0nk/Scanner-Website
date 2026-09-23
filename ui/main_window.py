from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.version import __version__

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
    border-bottom: 1px solid {LINE};
}}
QFrame#navDivider {{
    background: {LINE};
}}
QFrame#blankPage {{
    background: {BG};
    border: 0;
}}

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

        # Deliberately empty. Modules will be rebuilt one-by-one after navbar approval.
        blank = QFrame()
        blank.setObjectName("blankPage")
        blank.setFixedSize(DESIGN_WIDTH, DESIGN_HEIGHT - NAVBAR_HEIGHT)
        root.addWidget(blank)

        viewport.setWidget(canvas)
        self.setCentralWidget(viewport)

        self.refresh_nav_state()

    def build_navbar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("navbar")
        bar.setFixedSize(DESIGN_WIDTH, NAVBAR_HEIGHT)

        root = QHBoxLayout(bar)
        root.setContentsMargins(18, 0, 18, 0)
        root.setSpacing(0)

        # ---- Brand -------------------------------------------------------
        brand = QWidget()
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
        nav_rail = QWidget()
        nav_width = sum(width for _, width in self.NAV_ITEMS)
        nav_rail.setFixedSize(nav_width, NAVBAR_HEIGHT)
        nav_layout = QHBoxLayout(nav_rail)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(0)

        for item_name, width in self.NAV_ITEMS:
            btn = QPushButton(item_name)
            btn.setObjectName("navItem")
            btn.setFixedSize(width, NAVBAR_HEIGHT)
            btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            btn.setFocusPolicy(Qt.NoFocus)
            btn.clicked.connect(lambda _checked=False, n=item_name: self.select_nav(n))
            self.nav_buttons[item_name] = btn
            nav_layout.addWidget(btn)

        root.addWidget(nav_rail)
        root.addStretch(1)

        # ---- Utilities --------------------------------------------------
        for glyph in ("◉", "☾", "⚙"):
            btn = QPushButton(glyph)
            btn.setObjectName("navUtility")
            btn.setFixedSize(34, 34)
            btn.setToolTip(glyph)
            root.addWidget(btn)
            root.addSpacing(4)

        return bar

    def select_nav(self, name: str) -> None:
        self.active_nav = name
        self.refresh_nav_state()

    def refresh_nav_state(self) -> None:
        for name, button in self.nav_buttons.items():
            button.setObjectName("navItemActive" if name == self.active_nav else "navItem")
            button.style().unpolish(button)
            button.style().polish(button)
            button.update()

