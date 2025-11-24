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
        self.caching = None
        self.StorageManager = None
        self.authandkeyhandler = None
        self.ssl_context = None
        self.host = '::1'
        self.UTC_Thread = None

        # Initialization previously done in __init__ now moved to lifespan
        # to let uvicorn control startup/shutdown.

    def get_ssl_context(self) -> None:
        """
        Loads the SSL context.
        On Azure (and most cloud providers), SSL is terminated at the load balancer.
        The internal server should usually run on HTTP.
        """
        # If running locally, use certificates.
        # If running on Azure, os.environ.get('WEBSITE_SITE_NAME') will likely be present.
        if not os.environ.get('WEBSITE_SITE_NAME'): 
            try:
                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self.ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')
            except Exception as e:
                print(f"Warning: SSL context not loaded (Local certs missing?): {e}")
                self.ssl_context = None
        else:
            # On Azure, disable internal SSL
            self.ssl_context = None

    def server_initiator(self) -> None:
        """
        Initializes the server resources.
        """
        self.DB = DB_connect.DB_connect()
        self.caching = caching_module.caching(self.DB)
        self.StorageManager = StorageManager.StorageManager(self.DB)
        self.authandkeyhandler = Authenticator.AuthenticatorAndKeyHandler(self.caching, self.StorageManager)
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
        user_id = await self.authandkeyhandler.handle_authentication(websocket)
        if user_id:
            loop = asyncio.get_running_loop()
            socket_handler = Socket.Server(websocket=websocket,
                                           caching=self.caching,
                                           loop=loop,
                                           storage_manager=self.StorageManager)
            self.caching.update_active_user_handler(websocket, socket_handler)
            
            # Start the thread first, so it's ready to process the queue.
            socket_handler.associated_thread = threading.Thread(target=socket_handler.start, name=f"SocketHandler_{user_id}")
            socket_handler.associated_thread.daemon = True
            socket_handler.associated_thread.start()

            # Now, with the thread running, trigger retrieval of cached messages.
            await asyncio.to_thread(self.caching.retrieve_cached_messages, receiver_id=user_id)
            
            # Wait for the thread to signal that it's finished.
            await socket_handler.finished.wait()
        else:
            # If authentication fails, handle_authentication now returns None
            # and has already closed the connection.
            print("Authentication failed. Connection closed.")


    def user_thread_checker(self) -> None:
        """
        Continuously checks user_thread to see if the user is still connected or not.
        :return None:
        """
        while True:
            try:
                # Use thread-safe method to get a snapshot of active websockets
                for ws in self.caching.get_all_active_users_websockets():
                    active_user_info = self.caching.get_active_user_info(ws)
                    if active_user_info and active_user_info[1]: # active_user_info[1] is the socket_handler
                        socket_handler_instance = active_user_info[1]
                        if not socket_handler_instance.associated_thread.is_alive():
                            socket_handler_instance.associated_thread.join(timeout=1.0)
                            print(f"User {active_user_info[0]} (ws: {ws.remote_address}) has been disconnected and all threads are cleared.")
                            self.caching.remove_active_user(ws) # Use thread-safe method to remove
                    else: # If info or handler is missing, remove the entry
                        self.caching.remove_active_user(ws)
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

            client_info = scope.get("client")
            if client_info:
                self.remote_address = f"{client_info[0]}:{client_info[1]}"
            else:
                self.remote_address = "Unknown_address"

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

# - Run in terminal using the alias "runserver"
