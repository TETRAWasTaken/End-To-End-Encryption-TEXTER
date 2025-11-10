import sys
import qasync
import asyncio
from PySide6.QtWidgets import QApplication
from Client.core.app_controller import AppController

def main():
    app = QApplication(sys.argv)

    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    controller = AppController()
    controller.run()

    with loop:
        sys.exit(loop.run_forever())

if __name__ == "__main__":
    main()