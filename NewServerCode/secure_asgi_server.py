import asyncio
import os
import ssl
import sys
import threading
from typing import Callable, Awaitable, Dict, Any

from NewServerCode import Authenticator
from database import StorageManager
from database import DB_connect
from NewServerCode import Socket
from NewServerCode import caching as caching_module

# ASGI application compatible with uvicorn while preserving existing architecture.


class Server:
    def __init__(self):
        # Objects
        self.DB = None
        self.cacheDB = None
        self.caching = None
        self.StorageManager = None
        self.KeyStorage = None
        self.authandkeyhandler = None
        self.ssl_context = None
        self.host = '::1'
        self.UTC_Thread = None

        # Initialization previously done in __init__ now moved to lifespan
        # to let uvicorn control startup/shutdown.

    def get_ssl_context(self) -> None:
        """
        Loads the SSL context from the server.crt and server.key files.
        Note: With uvicorn, prefer passing ssl args to uvicorn instead of using this.
        """
        try:
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        except Exception as e:
            print(f"Error while loading SSL context: {e}")
            sys.exit(1)

    def server_initiator(self) -> None:
        """
        Initializes the server resources.
        """
        self.DB = DB_connect.DB_connect()
        self.cacheDB = DB_connect.DB_connect()
        self.caching = caching_module.caching(self.DB, self.cacheDB)
        self.StorageManager = StorageManager.StorageManager(self.DB)
        self.authandkeyhandler = Authenticator.AuthenticatorAndKeyHandler(self.caching, self.KeyStorage)
        print("Database connection established.")

        self.UTC_Thread = threading.Thread(target=self.user_thread_checker, name="UserThreadChecker")
        self.UTC_Thread.daemon = True
        self.UTC_Thread.start()

    async def authenticator(self, websocket) -> None:
        """
        Wrapper that delegates the connection to AuthenticatorHandlerAndKeyHandler
        :param websocket: websocket connection instance of the client
        :return: None
        """
        loop = asyncio.get_running_loop()
        if await self.authandkeyhandler.handle_authentication(websocket, loop):
            socket_handler = Socket.Server(websocket=websocket, caching=self.caching, loop=loop)
            socket_handler.associated_thread = threading.Thread(target=socket_handler.start)
            socket_handler.associated_thread.daemon = True
            socket_handler.associated_thread.start()
            # Preserve original behavior of tracking active users
            self.caching.ACTIVEUSERS[websocket][1].append(socket_handler)
        else:
            await websocket.send((self.caching.payload("error", "Authentication Failed")))
            await websocket.close()

    def user_thread_checker(self) -> None:
        """
        Continuously checks user_thread to see if the user is still connected or not.
        :return None:
        """
        while True:
            try:
                for i in list(self.caching.ACTIVEUSERS.keys()):
                    socket_handler_instance = self.caching.ACTIVEUSERS[i][1]
                    if not socket_handler_instance.associated_thread.is_alive():
                        socket_handler_instance.associated_thread.join(timeout=1.0)
                        print(f"User {i} has been disconnected and all threads are cleared.")
                        del self.caching.ACTIVEUSERS[i]
                # Keep the original cadence
                import time
                time.sleep(5)
            except (RuntimeError, KeyError) as e:
                print(f"Error in user_thread_checker: {e}")
                continue
            except Exception as e:
                print(f"Error : {e}")


# ---- ASGI app adapter ----

_server_singleton = Server()


async def _lifespan(scope: Dict[str, Any], receive: Callable[[], Awaitable[Dict[str, Any]]], send: Callable[[Dict[str, Any]], Awaitable[None]]):
    """
    ASGI lifespan handler: initializes and cleans up resources.
    """
    assert scope["type"] == "lifespan"
    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            # Initialize existing components here (instead of __init__ running loops)
            _server_singleton.server_initiator()
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            # If you add graceful shutdown logic later, place it here.
            await send({"type": "lifespan.shutdown.complete"})
            return


async def _websocket(scope: Dict[str, Any], receive: Callable[[], Awaitable[Dict[str, Any]]], send: Callable[[Dict[str, Any]], Awaitable[None]]):
    """
    ASGI WebSocket handler that adapts the existing websocket interface expected by authenticator().
    """
    assert scope["type"] == "websocket"

    # Accept the connection first (authenticator will close if needed)
    await send({"type": "websocket.accept"})

    # Minimal adapter to look like the original "websockets" interface that the code expects.
    class ASGIWebSocketAdapter:
        def __init__(self, scope, receive, send):
            self._scope = scope
            self._receive = receive
            self._send = send
            self._closed = False

        async def recv(self):
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
            if isinstance(data, (bytes, bytearray)):
                await self._send({"type": "websocket.send", "bytes": bytes(data)})
            else:
                await self._send({"type": "websocket.send", "text": str(data)})

        async def close(self, code: int = 1000):
            if not self._closed:
                self._closed = True
                await self._send({"type": "websocket.close", "code": code})

        # Provide minimal mapping-like API if original code indexes ACTIVEUSERS by websocket object
        def __repr__(self):
            return f"<ASGIWebSocketAdapter path={self._scope.get('path')!r}>"

    websocket = ASGIWebSocketAdapter(scope, receive, send)

    try:
        await _server_singleton.authenticator(websocket)
    except ConnectionError:
        # Client disconnected; ensure closed state
        await websocket.close()
    except Exception as e:
        # On error, try to notify and close
        try:
            await websocket.send("Internal server error")
        finally:
            await websocket.close()
        print(f"WebSocket error: {e}")


async def app(scope: Dict[str, Any], receive: Callable[[], Awaitable[Dict[str, Any]]], send: Callable[[Dict[str, Any]], Awaitable[None]]):
    """
    ASGI application entry point for uvicorn.
    - Handles lifespan for startup/shutdown.
    - Routes all websocket connections to the existing authenticator flow via an adapter.
    """
    if scope["type"] == "lifespan":
        await _lifespan(scope, receive, send)
    elif scope["type"] == "websocket":
        await _websocket(scope, receive, send)
    else:
        # Optionally respond for HTTP with 404 or simple health
        if scope["type"] == "http":
            # Simple 200 OK for health checks
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain; charset=utf-8")]})
            await send({"type": "http.response.body", "body": b"OK"})
        else:
            # Unknown scope type
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b""})


# Note:
# - Run with: uvicorn NewServerCode.NewServer:app --host 0.0.0.0 --port ${PORT:-12345}
# - If you need TLS via uvicorn: add --ssl-keyfile server.key --ssl-certfile server.crt
# - PORT env var is read by your Procfile/launcher; uvicorn handles it directly.
