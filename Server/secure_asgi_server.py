import asyncio
import os
import ssl
from typing import Callable, Awaitable, Dict, Any

from Server import Authenticator
from database import StorageManager
from database import DB_connect
from Server import Socket
from Server import caching as caching_module


class Server:
    """
    Manages the overall state and lifecycle of the secure chat server.

    This class is responsible for initializing server resources, loading SSL
    context, and handling the main authentication and connection logic. It acts
    as a central coordinator for various server components like the database,
    caching, and authentication handlers.
    """
    def __init__(self):
        """
        Initializes the Server instance, setting up placeholder attributes for
        its components.
        """
        self.DB = None
        self.caching = None
        self.StorageManager = None
        self.authandkeyhandler = None
        self.ssl_context = None
        self.host = '::1'

    def get_ssl_context(self) -> None:
        """
        Loads the SSL context from certificate and key files.

        This method attempts to load 'server.crt' and 'server.key' to create an
        SSL context for secure communication. If the files are not found or an
        error occurs, a warning is printed, and the server proceeds without SSL.
        """
        if not os.environ.get('WEBSITE_SITE_NAME'):
            try:
                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self.ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')
            except Exception as e:
                print(f"Warning: SSL context not loaded (Local certs missing?): {e}")
                self.ssl_context = None
        else:
            self.ssl_context = None

    def server_initiator(self) -> None:
        """
        Initializes the server's core components.

        This method sets up the database connection, caching mechanism, storage
        manager, and the authentication and key handler. It's a critical part
        of the server's startup sequence.
        """
        self.DB = DB_connect.DB_connect()
        self.caching = caching_module.caching(self.DB)
        self.StorageManager = StorageManager.StorageManager(self.DB)
        self.authandkeyhandler = Authenticator.AuthenticatorAndKeyHandler(self.caching, self.StorageManager)
        print("Database connection established.")

    async def authenticator(self, websocket) -> None:
        """
        Authenticates a new WebSocket connection and hands it off.

        This method serves as the entry point for new client connections. It
        uses the AuthenticatorAndKeyHandler to authenticate the user. If
        successful, it creates a new Socket.Server instance to handle the
        connection and retrieves any cached messages for the user.

        Args:
            websocket: The WebSocket connection object for the client.
        """
        user_id = await self.authandkeyhandler.handle_authentication(websocket)
        if user_id:
            loop = asyncio.get_running_loop()
            socket_handler = Socket.Server(websocket=websocket,
                                           cache=self.caching,
                                           loop=loop,
                                           storage_manager=self.StorageManager)
            self.caching.update_active_user_handler(websocket, socket_handler)

            await asyncio.to_thread(self.caching.retrieve_cached_messages, receiver_id=user_id)

            try:
                await socket_handler.start()
            finally:
                print(f"Cleaning up active user {user_id}")
                self.caching.remove_active_user(websocket)
        else:
            print("Authentication failed. Connection closed.")


_server_singleton = Server()


async def _lifespan(scope: Dict[str, Any], receive: Callable[[], Awaitable[Dict[str, Any]]],
                    send: Callable[[Dict[str, Any]], Awaitable[None]]):
    """
    Handles the ASGI lifespan protocol for server startup and shutdown events.

    Args:
        scope: The ASGI connection scope.
        receive: The ASGI receive channel.
        send: The ASGI send channel.
    """
    assert scope["type"] == "lifespan"
    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            _server_singleton.server_initiator()
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
            return


async def _websocket(scope: Dict[str, Any], receive: Callable[[], Awaitable[Dict[str, Any]]],
                     send: Callable[[Dict[str, Any]], Awaitable[None]]):
    """
    Handles incoming WebSocket connections.

    Args:
        scope: The ASGI connection scope.
        receive: The ASGI receive channel.
        send: The ASGI send channel.
    """
    assert scope["type"] == "websocket"
    await send({"type": "websocket.accept"})

    class ASGIWebSocketAdapter:
        """
        Adapts the ASGI WebSocket interface to a more traditional WebSocket API.

        This class provides a simplified, familiar interface (recv, send, close)
        over the underlying ASGI receive and send callables. It handles the
        details of the ASGI WebSocket message format, making the application
        logic cleaner and more focused.
        """
        def __init__(self, scope, receive, send):
            self._scope = scope
            self._receive = receive
            self._send = send
            self._closed = False
            client_info = scope.get("client")
            if client_info:
                self.remote_address = f"{client_info[0]}:{client_info[1]}"
            else:
                self.remote_address = "Unknown_address"

        async def recv(self):
            """Receives a message from the WebSocket."""
            while True:
                msg = await self._receive()
                t = msg["type"]
                if t == "websocket.receive":
                    if "text" in msg and msg["text"] is not None:
                        return msg["text"]
                    if "bytes" in msg and msg["bytes"] is not None:
                        return msg["bytes"]
                elif t == "websocket.disconnect":
                    raise ConnectionError("WebSocket disconnected")

        async def send(self, data):
            """Sends a message over the WebSocket."""
            if isinstance(data, (bytes, bytearray)):
                await self._send({"type": "websocket.send", "bytes": bytes(data)})
            else:
                await self._send({"type": "websocket.send", "text": str(data)})

        async def close(self, code: int = 1000):
            """Closes the WebSocket connection."""
            if not self._closed:
                self._closed = True
                await self._send({"type": "websocket.close", "code": code})

        def __iter__(self):
            return self

        def __aiter__(self):
            return self

        async def __anext__(self):
            try:
                return await self.recv()
            except ConnectionError:
                raise StopAsyncIteration

        def __repr__(self):
            return f"<ASGIWebSocketAdapter path={self._scope.get('path')!r}>"

    websocket = ASGIWebSocketAdapter(scope, receive, send)

    try:
        await _server_singleton.authenticator(websocket)
    except ConnectionError:
        await websocket.close()
    except Exception as e:
        try:
            await websocket.send("Internal server error")
        finally:
            await websocket.close()
        print(f"WebSocket error: {e}")


async def app(scope: Dict[str, Any], receive: Callable[[], Awaitable[Dict[str, Any]]],
              send: Callable[[Dict[str, Any]], Awaitable[None]]):
    """
    The main ASGI application entry point.

    This function routes incoming connections based on their type. It handles
    the server's lifespan events (startup and shutdown), WebSocket connections,
    and basic HTTP requests.

    Args:
        scope: A dictionary containing information about the connection.
        receive: An awaitable callable to receive messages.
        send: An awaitable callable to send messages.
    """
    if scope["type"] == "lifespan":
        await _lifespan(scope, receive, send)
    elif scope["type"] == "websocket":
        await _websocket(scope, receive, send)
    else:
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"text-plain; charset=utf-8")]})
            await send({"type": "http.response.body", "body": b"OK"})
        else:
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b""})