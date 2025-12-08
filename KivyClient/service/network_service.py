from __future__ import annotations
import asyncio
import os
import threading
import ssl
import json
import websockets
from kivy.event import EventDispatcher
from kivy.clock import Clock


class NetworkService(EventDispatcher):
    # Define events
    __events__ = (
        'on_connected',
        'on_disconnected',
        'on_reconnecting',
        'on_message_received',
        'on_error_occurred'
    )

    def __init__(self, host_uri="textere2ee-hvbahvb0gzfrf4bb.centralindia-01.azurewebsites.net"):
        # Initialize EventDispatcher (Required for dispatch to work)
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

    # Default handlers (Required by Kivy)
    def on_connected(self, *args):
        pass

    def on_disconnected(self, *args):
        pass

    def on_reconnecting(self, *args):
        pass

    def on_message_received(self, message, *args):
        pass

    def on_error_occurred(self, error, *args):
        pass

    def set_credentials(self, username: str, password: str):
        self._saved_username = username
        self._saved_password = password

    def set_session_token(self, token: str):
        self.session_token = token

    def start(self):
        if not self._thread.is_alive():
            self._shutdown_event.clear()
            self._thread.start()
            # Wait briefly for loop to start
            if not self._loop_started.wait(timeout=5):
                Clock.schedule_once(lambda dt: self.dispatch('on_error_occurred', "Network thread failed to start."))

    def _run_event_loop(self):
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
        while not self._shutdown_event.is_set():
            await asyncio.sleep(0.1)

    def schedule_task(self, coro):
        if self.loop and self.loop.is_running():
            return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def _create_ssl_context(self):
        import certifi
        try:
            cafile = certifi.where()
            if os.path.exists(cafile):
                self.ssl_context = ssl.create_default_context(cafile=cafile)
            else:
                self.ssl_context = ssl.create_default_context()
        except:
            self.ssl_context = ssl.create_default_context()

    async def _connection_manager(self):
        self._should_reconnect = True
        while self._should_reconnect:
            try:
                self.websocket = await websockets.connect(self.host_uri, ssl=self.ssl_context)

                # Dispatch on_connected safely on the main thread
                Clock.schedule_once(lambda dt: self.dispatch('on_connected'))

                if self.session_token:
                    await self.websocket.send(json.dumps({
                        "command": "token_login",
                        "token": self.session_token
                    }))
                elif self._saved_username and self._saved_password:
                    await self.websocket.send(json.dumps({
                        "command": "login",
                        "credentials": {"username": self._saved_username, "password": self._saved_password}
                    }))

                await self.listen()

            except Exception as e:
                Clock.schedule_once(lambda dt: self.dispatch('on_error_occurred', f"Connection failed: {e}"))
                Clock.schedule_once(lambda dt: self.dispatch('on_disconnected'))

            if self.websocket:
                try:
                    await self.websocket.close()
                except:
                    pass
                self.websocket = None

            Clock.schedule_once(lambda dt: self.dispatch('on_disconnected'))

            if self._should_reconnect:
                Clock.schedule_once(lambda dt: self.dispatch('on_reconnecting'))
                await asyncio.sleep(5)

    async def listen(self):
        try:
            async for message in self.websocket:
                msg_json = json.loads(message)
                Clock.schedule_once(lambda dt: self.dispatch('on_message_received', msg_json))
        except Exception as e:
            if self._should_reconnect:
                Clock.schedule_once(lambda dt: self.dispatch('on_error_occurred', f"Listen error: {e}"))

    async def _send_payload(self, payload: str):
        if self.websocket:
            try:
                await self.websocket.send(payload)
            except Exception as e:
                Clock.schedule_once(lambda dt: self.dispatch('on_error_occurred', f"Send error: {e}"))

    def connect(self):
        self.schedule_task(self._connection_manager())

    def send_payload(self, payload: str):
        self.schedule_task(self._send_payload(payload))

    def logout(self):
        self._should_reconnect = False
        if self.websocket and self.session_token:
            self.schedule_task(self._send_payload(json.dumps({
                "command": "logout",
                "token": self.session_token
            })))
        self._saved_username = None
        self._saved_password = None
        self.session_token = None

    def shutdown(self):
        if self.loop and self._thread.is_alive():
            self.loop.call_soon_threadsafe(self._shutdown_event.set)
            self._thread.join(timeout=5)