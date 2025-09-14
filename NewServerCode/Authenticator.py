import threading

import websockets
import json
import asyncio
from Server import cache_managment_system, Socket
from X3DH import KeyStorage

class authenticator:
    def __init__(self, CMS: cache_managment_system.CACHEManager_Handler,
                 KeyStorage: KeyStorage.KeyStorage) -> None:
        """
        Initialises the authenticator.
        :param CMS: The cache management system instance
        :param KeyStorage: The key storage instance
        """
        self.CMS = CMS
        self.KeyStorage = KeyStorage

    async def handle_authentication(self, websocket: websockets,
                                    loop: asyncio.get_running_loop):
        """
        Handle the authentication of the client
        :param websocket: The websocket instance
        :param loop: The asyncio event loop
        """
        print(f"New connection from {websocket.remote_address}")
        authenticated_and_handled = False
        try:
            while not authenticated_and_handled:
                command = await websocket.recv()

                if command == "login":
                    print(f"Login requested by {websocket.remote_address}")
                    cred = await websocket.recv()
                    cred = json.loads(cred)
                    user = cred["username"]
                    passw = cred["password"]

                    if not user or not passw:
                        await websocket.send(self.CMS.payload("error", "Invalid format"))
                        continue

                    try:
                        if self.CMS.credentials[user] == passw:
                            await websocket.send(self.CMS.payload("ok", "success"))

                            socket_handler = Socket.Server(websocket=websocket, cms=self.CMS, loop=loop, KeyStorage=KeyStorage)
                            socket_handler.associated_thread = threading.Thread(target=socket_handler.start)
                            socket_handler.associated_thread.daemon = True
                            socket_handler.associated_thread.start()

                            print(f"User {user} logged in and handed over to socket handler.")
                            authenticated_and_handled = True

                            await websocket.wait_closed()

                        else:
                            print(f"Credentials don't match for client {websocket.remote_address}")
                            await websocket.send(self.CMS.payload("error", "Credfail"))

                    except KeyError:
                        print(f"Account not found for {user if user else 'unknown'}")
                        await websocket.send(self.CMS.payload("error", "NAF"))

                elif command == "reg":
                    print(f"Registration requested by {websocket.remote_address}")
                    cred = await websocket.recv()
                    cred = json.loads(cred)
                    user = cred["username"]
                    passw = cred["password"]

                    if not user or not passw:
                        await websocket.send(self.CMS.payload("error", "Invalid format"))
                        continue

