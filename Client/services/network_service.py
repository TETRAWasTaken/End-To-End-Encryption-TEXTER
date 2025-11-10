from __future__ import annotations

import asyncio
import ssl
import websockets
import json
from PySide6.QtCore import QObject, Signal

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

    def __init__(self, host_uri = "", myself = ""):
        """
        Initializes the network thread
        :param on_message_callback: The function to call when a message is received
        """
        super().__init__()
        self.websocket = None
        self.host_uri = host_uri
        self.myself = myself
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ssl_context.load_verify_locations(cafile='Client/services/server.crt')

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

    @staticmethod
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

    async def connect(self, **kwargs):
        """
        Connects to the server
        """
        try:
            self.websocket = await websockets.connect(self.host_uri, ssl=self.ssl_context)
            self.connected.emit()
            asyncio.create_task(self.listen())
        except Exception as e:
            self.error_occured.emit(f"Connect Failed : {str(e)}")

    async def listen(self):
        """
        Listens for messages from the server
        """
        try:
            async for message in self.websocket:
                try:
                    message = json.loads(message)
                    self.message_received.emit(message)
                except json.JSONDecodeError:
                    self.error_occured.emit(f"Invalid JSON Received : {message}")
        except websockets.exceptions.ConnectionClosed:
            self.disconnected.emit()
        except Exception as e:
            self.error_occured.emit(f"Error in listen : {str(e)}")
            self.disconnected.emit()

    async def send_payload(self, payload: json.dumps):
        """
        Sends a payload to the server
        """
        if self.websocket:
            try:
                await self.websocket.send(payload)
            except Exception as e:
                self.error_occured.emit(f"Error in send_payload : {str(e)}")

    async def send_raw(self, message):
        """
        Sends a raw message to the server
        """
        if self.websocket:
            try:
                await self.websocket.send(message)
            except Exception as e:
                self.error_occured.emit(f"Error in send_raw : {str(e)}")