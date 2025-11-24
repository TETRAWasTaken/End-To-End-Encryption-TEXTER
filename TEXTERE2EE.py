import sys
import qasync
import asyncio
from PySide6.QtWidgets import QApplication
from Client.core.app_controller import AppController

global app, controller, loop

if __name__ == "__main__":
    try:
        # 1. Create the Qt Application
        app = QApplication(sys.argv)

        app.setApplicationName("TEXTERE2EE")
        app.setOrganizationName("Anshumaan Soni")

        # 2. Prevent app from quitting when we close the login window
        app.setQuitOnLastWindowClosed(True)

        # 3. Create the qasync Event Loop
        loop = qasync.QEventLoop(app)

        # 4. Set this as the one and only asyncio event loop
        asyncio.set_event_loop(loop)

        # 5. Create the main controller (it's now saved in the global 'controller' variable)
        controller = AppController()
        controller.setParent(app)

        app.aboutToQuit.connect(controller.shutdown)

        # 6. Start the controller's logic
        controller.run()

        # 7. Start the event loop
        with loop:
            sys.exit(loop.run_forever())

    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        sys.exit(0)