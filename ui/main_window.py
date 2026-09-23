from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QPoint
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
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

        # Dashboard: intentionally minimal. The first dashboard milestone is
        # the KCONK project identity card; functional modules will be added later.
        self.dashboard_page = self.build_dashboard()
        root.addWidget(self.dashboard_page)

        viewport.setWidget(canvas)
        self.setCentralWidget(viewport)

        self.refresh_nav_state()


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
        settings_btn.clicked.connect(self.show_settings_notice)
        root.addWidget(settings_btn)
        root.addSpacing(4)

        outer.addWidget(row)

        bottom_line = QFrame()
        bottom_line.setObjectName("navBottomLine")
        bottom_line.setFixedSize(DESIGN_WIDTH, 1)
        outer.addWidget(bottom_line)

        return bar

    def set_theme(self, theme: str) -> None:
        """Switch the application palette without changing the fixed geometry."""
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
        STYLE = f"""
QMainWindow, QWidget {{ background: {BG}; color: {TEXT}; font-family: 'DejaVu Sans'; }}
QLabel {{ background: transparent; }}
QScrollArea {{ border: 0; background: {BG}; }}
QFrame#navbar {{ background: {NAV_BG}; border: 0; }}
QWidget#navRow {{ background: {NAV_BG}; }}
QFrame#navBottomLine {{ background: {LINE}; border: 0; }}
QFrame#navDivider {{ background: {LINE}; }}
QFrame#dashboardPage {{ background: {BG}; border: 0; }}
QFrame#projectCard {{ background: #081b14; border: 1px solid #315944; border-radius: 18px; }}
QFrame#cardDivider {{ background: #315944; border: 0; }}
QWidget#navBrand, QWidget#navRail {{ background: transparent; }}
QPushButton#navItem {{ background: transparent; border: 0; border-bottom: 2px solid transparent; color: {TEXT_DIM}; padding: 0 4px; margin: 0; font-size: 11px; font-weight: 700; }}
QPushButton#navItem:hover {{ background: {NAV_BG_ACTIVE}; color: {TEXT}; }}
QPushButton#navItemActive {{ background: {NAV_BG_ACTIVE}; border: 0; border-bottom: 2px solid {GOLD_BRIGHT}; color: {GOLD_BRIGHT}; padding: 0 4px; margin: 0; font-size: 11px; font-weight: 800; }}
QPushButton#navUtility {{ background: transparent; border: 0; border-radius: 7px; color: {GOLD}; font-size: 16px; padding: 0; }}
QPushButton#navUtility:hover {{ background: {NAV_BG_ACTIVE}; color: {GOLD_BRIGHT}; }}
"""
        self.setStyleSheet(STYLE)
        # Rebuild only the Dashboard page so its inline text/card colors follow
        # the selected theme; the navbar instance and its current order remain intact.
        if hasattr(self, "root_layout") and hasattr(self, "dashboard_page"):
            old_page = self.dashboard_page
            self.root_layout.removeWidget(old_page)
            old_page.deleteLater()
            self.dashboard_page = self.build_dashboard()
            self.root_layout.addWidget(self.dashboard_page)
        self.refresh_nav_state()

    def show_settings_notice(self) -> None:
        # Settings is intentionally a harmless UI affordance for now.
        self.statusBar().showMessage("Settings panel will be added in a later module.", 2500)

    def nav_order_changed(self, order) -> None:
        """Keep the active state intact after a drag reorder."""
        self.nav_buttons = self.nav_rail.buttons
        self.refresh_nav_state()

    def select_nav(self, name: str) -> None:
        self.active_nav = name
        self.refresh_nav_state()

    def refresh_nav_state(self) -> None:
        for name, button in self.nav_buttons.items():
            button.setObjectName("navItemActive" if name == self.active_nav else "navItem")
            button.style().unpolish(button)
            button.style().polish(button)
            button.update()

