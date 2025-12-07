
from __future__ import annotations

import asyncio
import os
import threading
import ssl
import json
from PySide6.QtCore import QObject, Signal, Slot
import websockets

class NetworkService(QObject):
    """
    Manages the WebSocket connection and communication in a separate thread.

    This class handles the asyncio event loop, connection, disconnection,
    sending, and receiving of messages, ensuring that the main GUI thread
    remains unblocked. It emits signals to notify the application of network
    events.
    """
    connected = Signal()
    disconnected = Signal()
    reconnecting = Signal()
    message_received = Signal(dict)
    error_occured = Signal(str)

    def __init__(self, host_uri="textere2ee-hvbahvb0gzfrf4bb.centralindia-01.azurewebsites.net"):
        """
        Initializes the NetworkService.

        Args:
            host_uri: The URI of the WebSocket server.
        """
        super().__init__()
        self._should_reconnect = None
        self.websocket = None
        self.host_uri = 'wss://' + host_uri
        self._create_ssl_context()

        self.loop = None
        self._thread = threading.Thread(target=self._run_event_loop, daemon=True)
        self._shutdown_event = threading.Event()
        self._loop_started = threading.Event()

        self._saved_username = None
        self._saved_password = None
        self.session_token = None

    def set_credentials(self, username: str, password: str):
        """
        Stores the username and password of the user temporarily in memory
        """
        self._saved_username = username
        self._saved_password = password

    def set_session_token(self, token: str):
        """
        is Called when the login response contains a Token
        """
        self.session_token = token

    def start(self):
        """Starts the background network thread."""
        if not self._thread.is_alive():
            self._shutdown_event.clear()
            self._thread.start()
            if not self._loop_started.wait(timeout=5):
                print("FATAL: Network service event loop failed to start.")
                self.error_occured.emit("Network thread failed to start.")

    def _run_event_loop(self):
        """The target method for the background thread, running the asyncio loop."""
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self._loop_started.set()
            self.loop.run_until_complete(self._main_loop())
        finally:
            if self.loop:
                for task in asyncio.all_tasks(loop=self.loop):
                    task.cancel()
                self.loop.run_until_complete(self.loop.shutdown_asyncgens())
                self.loop.close()
            asyncio.set_event_loop(None)

    async def _main_loop(self):
        """Keeps the event loop alive until a shutdown is requested."""
        while not self._shutdown_event.is_set():
            await asyncio.sleep(0.1)

    def schedule_task(self, coro):
        """
        Schedules a coroutine to run on the service's event loop.

        Args:
            coro: The coroutine to schedule.

        Returns:
            A future representing the execution of the coroutine.
        """
        if self.loop and self.loop.is_running():
            return asyncio.run_coroutine_threadsafe(coro, self.loop)
        else:
            print("NetworkService: Event loop is not running. Cannot schedule task.")

    def _create_ssl_context(self):
        """
        Creates an SSL context for the WebSocket connection, using certifi for
        certificate verification.
        """
        import certifi
        self.ssl_context = None
        try:
            cafile = certifi.where()
            if os.path.exists(cafile):
                os.environ['SSL_CERT_FILE'] = cafile
                os.environ['REQUESTS_CA_BUNDLE'] = cafile
                self.ssl_context = ssl.create_default_context(cafile=cafile)
            else:
                print(f"Certifi file not found at {cafile}. Switching to system default.")
                self.ssl_context = ssl.create_default_context()
        except Exception as e:
            print(f"Error loading certifi ({e}). Switching to system default.")
            self.ssl_context = ssl.create_default_context()

    @staticmethod
    def payload(status: str, message: str | dict) -> str:
        """
        Creates a standard JSON payload string.

        Args:
            status: The status code of the message (e.g., "ok", "error").
            message: The content of the message.

        Returns:
            A JSON string representing the payload.
        """
        return json.dumps({"status": status, "message": message}, ensure_ascii=False)

    def message_payload(self, sender_user_id: str, receiver_user_id: str, text: str) -> str:
        """
        Creates a specific JSON payload for an encrypted text message.

        Args:
            sender_user_id: The user ID of the sender.
            receiver_user_id: The user ID of the receiver.
            text: The encrypted message content.

        Returns:
            A JSON string representing the encrypted message payload.
        """
        text_payload = {"recv_user_id": receiver_user_id, "text": text, "sender_user_id": sender_user_id}
        return self.payload("Encrypted", text_payload)

    async def _connection_manager(self):
        """Asynchronously connects to the WebSocket server."""
        self._should_reconnect = True
        while self._should_reconnect:
            try:
                self.websocket = await websockets.connect(self.host_uri,
                                                          ssl=self.ssl_context,
                                                          open_timeout=10,
                                                          ping_interval=20,
                                                          ping_timeout=20)
                self.connected.emit()

                if self.session_token:
                    self.error_occured.emit("Auto-ReAuthenticating using session token...")
                    token_paylaod = {
                        "command": "token_login",
                        "token": self.session_token
                    }
                    await self.websocket.send(json.dumps(token_paylaod))

                elif self._saved_username and self._saved_password:
                    self.error_occured.emit("Auto-ReAuthenticating using credentials...")
                    login_payload = {
                        "command": "login",
                        "credentials": {
                            "username": self._saved_username,
                            "password": self._saved_password
                        }
                    }
                    await self.websocket.send(json.dumps(login_payload))

                await self.listen()

            except (websockets.exceptions.WebSocketException, OSError, asyncio.TimeoutError) as e:
                self.error_occured.emit(f"Connection failed: {e.__class__.__name__} - {e}")
                self.disconnected.emit()

            if self.websocket:
                try:
                    await self.websocket.close()
                except:
                    pass
                self.websocket = None

            self.disconnected.emit()

            if self._should_reconnect:
                self.reconnecting.emit()
                await asyncio.sleep(5)

    async def listen(self):
        """Listens for incoming messages from the server."""
        try:
            async for message in self.websocket:
                try:
                    self.message_received.emit(json.loads(message))
                except json.JSONDecodeError:
                    self.error_occured.emit(f"Invalid JSON Received : {message}")
        except websockets.exceptions.ConnectionClosed as e:
            print(f"Connection closed gracefully: {e.code} {e.reason}")
            self.disconnected.emit()
        except (websockets.exceptions.WebSocketException, OSError) as e:
            self.error_occured.emit(f"Error in listen : {str(e)}")
            self.disconnected.emit()

    async def _disconnect(self):
        """Asynchronously closes the WebSocket connection."""
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
            self.disconnected.emit()

    async def _send_payload(self, payload: str):
        """
        Asynchronously sends a JSON payload to the server.

        Args:
            payload: The JSON string to send.
        """
        if self.websocket:
            try:
                await self.websocket.send(payload)
            except websockets.exceptions.ConnectionClosed as e:
                self.error_occured.emit(f"Error in _send_payload : {str(e)}")

    async def _send_raw(self, message: str):
        """
        Asynchronously sends a raw string message to the server.

        Args:
            message: The raw string to send.
        """
        if self.websocket:
            try:
                await self.websocket.send(message)
            except websockets.exceptions.ConnectionClosed as e:
                self.error_occured.emit(f"Error in _send_raw : {str(e)}")

    async def _stop_connection(self):
        """
        Stops the reconnection loop
        """
        self._should_reconnect = False

        if self.websocket:
            try:
                await self.websocket.close()
            except Exception as e:
                self.error_occured.emit(f"Error in _stop_connection : {str(e)}")
            finally:
                self.websocket = None

        self.disconnected.emit()

    @Slot()
    def connect(self):
        """Public slot to schedule the connection to the server."""
        self.schedule_task(self._connection_manager())

    @Slot(str)
    def send_payload(self, payload: str):
        """
        Public slot to schedule a JSON payload to be sent.

        Args:
            payload: The JSON string to send.
        """
        self.schedule_task(self._send_payload(payload))

    @Slot(str)
    def send_raw(self, message: str):
        """
        Public slot to schedule a raw string message to be sent.

        Args:
            message: The raw string to send.
        """
        self.schedule_task(self._send_raw(message))

    @Slot()
    def shutdown(self):
        """Public slot to gracefully shut down the network thread."""
        if self.loop and self._thread.is_alive():
            self.schedule_task(self._disconnect())
            self.loop.call_soon_threadsafe(self._shutdown_event.set)
            self._thread.join(timeout=5)

    def logout(self):
        """
        Send the logout command, clears local tokens, and stops the connection loop
        """
        self._should_reconnect = False

        if self.websocket and self.session_token:
            try:
                logout_payload = {
                    "command": "logout",
                    "token": self.session_token
                }
                self.schedule_task(self._send_payload(json.dumps(logout_payload)))

            except Exception as e:
                self.error_occured.emit(f"Error in logout : {str(e)}")

        self._saved_username = None
        self._saved_password = None
        self.session_token = None

        self.schedule_task(self._stop_connection())