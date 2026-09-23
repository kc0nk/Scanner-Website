import sys
from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow
from app.version import __version__


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(f"KCONK Suite v{__version__}")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
