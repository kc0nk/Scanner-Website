from __future__ import annotations

import sys
import signal
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer
from ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("CTF Exploit Workbench v3.40")
    window = MainWindow()
    window.show()

    # Qt applications normally receive SIGINT (Ctrl+C) in the Python main
    # thread. The default Python handler raises KeyboardInterrupt, which can
    # interrupt QMainWindow.closeEvent() halfway through shutdown. Convert
    # SIGINT/SIGTERM into the same orderly Qt close path instead.
    shutting_down = {"requested": False}

    def request_close(_signum, _frame):
        if shutting_down["requested"]:
            return
        shutting_down["requested"] = True
        QTimer.singleShot(0, window.close)

    signal.signal(signal.SIGINT, request_close)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_close)

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
