import sys
import qasync
import asyncio
import os
import shutil
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QStandardPaths
from Client.core.app_controller import AppController

global app, controller, loop

if __name__ == "__main__":
    try:
        # 1. Create the Qt Application
        app = QApplication(sys.argv)

        app.setApplicationName("TEXTERE2EE")
        app.setOrganizationName("Anshumaan Soni")

        # --- Clean AppData for Dev ---
        if '--clean' in sys.argv:
            data_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation)
            if os.path.exists(data_dir):
                print(f"Dev Mode: Deleting old data directory: {data_dir}")
                shutil.rmtree(data_dir, ignore_errors=True)
        # --- End Clean ---

        # --- Apply Stylesheet ---
        try:
            stylesheet_path = os.path.join(os.path.dirname(__file__), "Client/gui/stylesheet.qss")
            with open(stylesheet_path, "r") as f:
                app.setStyleSheet(f.read())
        except FileNotFoundError:
            print("Stylesheet not found. Using default styles.")
        except Exception as e:
            print(f"Error loading stylesheet: {e}")

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
