from __future__ import annotations

import asyncio
import os
import threading
import ssl
import certifi
import websockets
import json
from PySide6.QtCore import QObject, Signal, Slot

"""
This class handles the asyncio event loop and all the communication, 
in a seperate thread, so it doesn't block the main GUI
"""

class NetworkService(QObject):
    """
    This class handles the asyncio event loop and all the communication,
    in a separate thread, so it doesn't block the main GUI
    """
    # Define Signals
    connected = Signal()
    disconnected = Signal()
    message_received = Signal(dict)
    error_occured = Signal(str)

    def __init__(self, host_uri = "textere2ee-hvbahvb0gzfrf4bb.centralindia-01.azurewebsites.net"):
        super().__init__()
        self.websocket = None
        self.host_uri = 'wss://' + host_uri
        self._create_ssl_context()

        # --- Threading and asyncio setup ---
        self.loop = None
        self._thread = threading.Thread(target=self._run_event_loop, daemon=True)
        self._shutdown_event = threading.Event()
        self._loop_started = threading.Event()

    def start(self):
        """Starts the network thread."""
        if not self._thread.is_alive():
            self._shutdown_event.clear()
            self._thread.start()
            if not self._loop_started.wait(timeout=5):  # Wait for loop to be ready
                # This is a critical failure, should be logged or raised
                print("FATAL: Network service event loop failed to start.")
                self.error_occured.emit("Network thread failed to start.")

    def _run_event_loop(self):
        """The target method for the background thread."""
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self._loop_started.set()  # Signal that the loop is ready
            # Run until the shutdown event is set
            self.loop.run_until_complete(self._main_loop())
        finally:
            if self.loop:
                # Ensure all tasks are cancelled before closing the loop
                for task in asyncio.all_tasks(loop=self.loop):
                    task.cancel()
                self.loop.run_until_complete(self.loop.shutdown_asyncgens())
                self.loop.close()
            asyncio.set_event_loop(None)

    async def _main_loop(self):
        """Keeps the event loop alive until shutdown is requested."""
        while not self._shutdown_event.is_set():
            await asyncio.sleep(0.1)

    def schedule_task(self, coro):
        """Schedules a coroutine to run on the service's event loop. This is thread-safe."""
        if self.loop and self.loop.is_running():
            return asyncio.run_coroutine_threadsafe(coro, self.loop)
        else:
            print("NetworkService: Event loop is not running. Cannot schedule task.")

    def _create_ssl_context(self):
        """
        Creates the SSL context, prioritizing certifi but falling back to system defaults
        to ensure the app works even if packaging breaks the cert file path.
        """
        import certifi
        import ssl
        import os

        self.ssl_context = None

        try:
            # Attempt 1: Use certifi
            cafile = certifi.where()
            if os.path.exists(cafile):
                # This fixes the "hang" by telling OpenSSL where the file is
                os.environ['SSL_CERT_FILE'] = cafile
                os.environ['REQUESTS_CA_BUNDLE'] = cafile
                self.ssl_context = ssl.create_default_context(cafile=cafile)
            else:
                print(f"Certifi file not found at {cafile}. Switching to system default.")
                self.ssl_context = ssl.create_default_context()

        except Exception as e:
            print(f"Error loading certifi ({e}). Switching to system default.")
            # Attempt 2: Fallback to System Default (System Trust Store)
            self.ssl_context = ssl.create_default_context()

    @staticmethod
    def payload(status: str, message: str | dict) -> str:
        """
        Describes the general payload of each message sent
        :param status: The basic code of a sent message, can be "error", "ok"
        :param message: The extra details that needs to be sent
        :return payload: A JSON string containing the status and message
        """

        payload = {
            "status": status,
            "message": message
        }
        return json.dumps(payload, ensure_ascii=False)

    def message_payload(self, sender_user_id: str, receiver_user_id: str, text: str) -> str:
        """
        A sub-json payload definition to send an encrypted text
        """
        text_payload = {
            "recv_user_id": receiver_user_id,
            "text": text,
            "sender_user_id": sender_user_id
        }

        return self.payload("Encrypted", text_payload)

    async def _connect(self, **kwargs):
        """
        Connects to the server
        """
        try:
            # clean connection logic without probes
            self.websocket = await websockets.connect(self.host_uri, ssl=self.ssl_context, open_timeout=10)
            self.connected.emit()
            self.schedule_task(self.listen())
        except (websockets.exceptions.WebSocketException, OSError, asyncio.TimeoutError) as e:
            error_msg = f"Connection failed: {e.__class__.__name__} - {e}"
            self.error_occured.emit(error_msg)
            self.disconnected.emit()

    async def listen(self):
        """
        Listens for messages from the server
        """
        try: #
            async for message in self.websocket:
                try:
                    message = json.loads(message)
                    print(f"Message Received : {message}")
                    self.message_received.emit(message)
                except json.JSONDecodeError: # Catching the error inside the loop
                    self.error_occured.emit(f"Invalid JSON Received : {message}")
        except websockets.exceptions.ConnectionClosed as e:
            print(f"Connection closed gracefully: {e.code} {e.reason}")
            self.disconnected.emit()
        except (websockets.exceptions.WebSocketException, OSError) as e:
            # Catch other potential network errors during listening
            self.error_occured.emit(f"Error in listen : {str(e)}")
            self.disconnected.emit()

    async def _disconnect(self):
        """Closes the websocket connection."""
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
            self.disconnected.emit()

    async def _send_payload(self, payload: json.dumps):
        """
        Sends a payload to the server
        """
        if self.websocket:
            try:
                await self.websocket.send(payload)
            except websockets.exceptions.ConnectionClosed as e:
                self.error_occured.emit(f"Error in _send_payload : {str(e)}")

    async def _send_raw(self, message):
        """
        Sends a raw message to the server
        """
        if self.websocket:
            try:
                await self.websocket.send(message)
            except websockets.exceptions.ConnectionClosed as e:
                self.error_occured.emit(f"Error in _send_raw : {str(e)}")

    # --- Public slots to be called from other threads ---

    @Slot()
    def connect(self):
        self.schedule_task(self._connect())

    @Slot(str)
    def send_payload(self, payload: str):
        self.schedule_task(self._send_payload(payload))

    @Slot(str)
    def send_raw(self, message: str):
        self.schedule_task(self._send_raw(message))

    @Slot()
    def shutdown(self):
        """Signals the event loop to shut down."""
        if self.loop and self._thread.is_alive():
            # Schedule disconnection and then set the shutdown event
            self.schedule_task(self._disconnect())
            self.loop.call_soon_threadsafe(self._shutdown_event.set)
            self._thread.join(timeout=5)  # Wait for thread to finish
            if self._thread.is_alive():
                print("Warning: Network thread did not shut down gracefully.")