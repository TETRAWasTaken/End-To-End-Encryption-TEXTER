import sys
import qasync
import asyncio
from PySide6.QtWidgets import QApplication
from Client.core.app_controller import AppController


async def main():
    """
    Asynchronous main function.
    """
    # Create the controller *after* the loop is running
    controller = AppController()
    controller.run()

    # This is a clean way to keep the event loop
    # running until the application is closed.
    await asyncio.get_event_loop().create_future()


if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)

        # qasync.run() will create and manage the event loop for you.
        qasync.run(main())

    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        sys.exit(0)