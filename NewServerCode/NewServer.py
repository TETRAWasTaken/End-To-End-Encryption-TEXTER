import asyncio
import ssl
import websockets
import sys
import threading
import time
import os
from NewServerCode import Authenticator

from database import StorageManager
from database import DB_connect

from NewServerCode import Socket
from NewServerCode import caching

"""
The main Server which would also work as the Load_Balancer for the system,
handling all the important task and managing the database as well.
"""

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

        # Methods
        self.get_ssl_context()
        self.server_initiator()


    def get_ssl_context(self) -> None:
        """
        Loads the SSL context from the server.crt and server.key files.
        :param: parent
        :return: None
        """
        try:
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        except Exception as e:
            print(f"Error while loading SSL context: {e}")
            sys.exit(1)

    def server_initiator(self) -> None:
        """
        Initializes the server.
        This includes; Database connection, StorageManager, KeyStorage, and CACHEManager.
        :param: parent
        :return: None
        """
        self.DB = DB_connect.DB_connect()
        self.cacheDB = DB_connect.DB_connect()
        self.caching = caching.caching(self.DB, self.cacheDB)
        self.StorageManager = StorageManager.StorageManager(self.DB)
        self.authandkeyhandler = Authenticator.AuthenticatorAndKeyHandler(self.caching, self.KeyStorage)
        print("Database connection established.")

        self.UTC_Thread = threading.Thread(target = self.user_thread_checker)
        self.UTC_Thread.daemon = True
        self.UTC_Thread.start()

        try:
            asyncio.run(self.start_server())
        except KeyboardInterrupt:
            print("Exiting...")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred: {e}")
            sys.exit(1)

    async def start_server(self) -> None:
        """
        Starts the main websocket server to listen for connection
        :param: parent
        :return: None
        """
        loop = asyncio.get_running_loop()
        print(f"Starting WebSocket server on {self.host}:12345 with SSL enabled. Waiting for connections...")
        async with websockets.serve(
            lambda websockets: self.authenticator(websockets),
            self.host,
            port = os.environ.get('PORT', 12345),
            ssl=self.ssl_context,
        ):
            await asyncio.Future()

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
                time.sleep(5)
            except (RuntimeError, KeyError) as e:
                print(f"Error in user_thread_checker: {e}")
                continue
            except Exception as e:
                print(f"Error : {e}")

if __name__=="__main__":
    server = Server()