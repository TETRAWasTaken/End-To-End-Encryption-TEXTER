from __future__ import annotations

import asyncio
import threading
import ssl
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
        self._loop_started = threading.Event()

    def start(self):
        """Starts the network thread."""
        if not self._thread.is_alive():
            self._thread.start()

    def _run_event_loop(self):
        """The target method for the background thread."""
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self._loop_started.set()  # Signal that the loop is ready
            self.loop.run_forever()
        finally:
            if self.loop:
                self.loop.close()

    def schedule_task(self, coro):
        """Schedules a coroutine to run on the service's event loop. This is thread-safe."""
        if not self._loop_started.wait(timeout=5):  # Wait up to 5 seconds for the loop
            print("NetworkService: Timed out waiting for the event loop to start.")
            return

        if self.loop and self.loop.is_running():
            return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def _create_ssl_context(self):
        self.ssl_context = ssl.create_default_context()

    @staticmethod
    def payload(status: str, message: str | dict) -> json.dumps:
        """
        Describes the general payload of each message sent
        :param status: The basic code of a sent message, can be "error", "ok"
        :param message: The extra details that needs to be sent
        :return payload: A JSON object containing the status and message
        """

        payload = {
            "status": status,
            "message": message
        }
        return json.dumps(payload)

    def message_payload(self, sender_user_id: str, receiver_user_id: str, text) -> json.dumps:
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
            self.websocket = await websockets.connect(self.host_uri, ssl=self.ssl_context)
            self.connected.emit()
            self.schedule_task(self.listen())
        except websockets.exceptions.ConnectionClosed as e:
            self.error_occured.emit(f"Connection Closed : {str(e)}")
            self.disconnected.emit()
            print(f"Connection Closed : {str(e)}")
        except Exception as e:
            self.error_occured.emit(f"Connect Failed : {str(e)}")

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
                except Exception as e:
                    self.error_occured.emit(f"Error in listen : {str(e)}")
        except websockets.exceptions.ConnectionClosed:
            self.disconnected.emit()
            print("Server Disconnected")
        except Exception as e:
            self.error_occured.emit(f"Error in listen : {str(e)}")
            self.disconnected.emit()

    async def _send_payload(self, payload: json.dumps):
        """
        Sends a payload to the server
        """
        if self.websocket:
            try:
                await self.websocket.send(payload)
            except Exception as e:
                self.error_occured.emit(f"Error in _send_payload : {str(e)}")

    async def _send_raw(self, message):
        """
        Sends a raw message to the server
        """
        if self.websocket:
            try:
                await self.websocket.send(message)
            except Exception as e:
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