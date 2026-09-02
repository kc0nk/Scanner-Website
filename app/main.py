import sys
from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow
from app.version import __version__

def main():
    app=QApplication(sys.argv); app.setApplicationName(f"CTF Exploit Workbench v{__version__}"); w=MainWindow(); w.show(); return app.exec()
if __name__=='__main__': raise SystemExit(main())
