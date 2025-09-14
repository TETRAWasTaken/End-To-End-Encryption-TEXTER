from __future__ import annotations
import threading
from typing import Any, Coroutine

import websockets
import json
import asyncio
from Server import cache_managment_system
from X3DH import KeyStorage

class AuthenticatorAndKeyHandler:
    def __init__(self, cms: cache_managment_system.CACHEManager_Handler,
                 keystorage: KeyStorage.KeyStorage) -> None:
        """
        Initializes the authenticator.
        :param cms: The cache management system instance
        :param keystorage: The key storage instance
        """
        self.CMS = cms
        self.KeyStorage = keystorage

    async def handle_authentication(self, websocket: websockets,
                                    loop: asyncio.get_running_loop) -> bool | None:
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
                            authenticated_and_handled = True
                            return True

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

                    if user in self.CMS.credentials:
                        await websocket.send(self.CMS.payload("error", "AAE"))
                        print(f"Registration failed, username {user} already exists")
                    else:
                        self.CMS.update_Credentials(user, passw)
                        await websocket.send(self.CMS.payload("ok", "Registration Successful"))
                        print(f"Registration successful for {user} from {websocket.remote_address}")

                        response = await websocket.recv()
                        if response == "publish_keys":
                            key_bundle = await websocket.recv()
                            key_bundle = json.loads(key_bundle)
                            print(f"Received key bundle from {websocket.remote_address}, user_id - {user}")
                            if self.KeyStorage.StoreUserKeyBundle(user,
                                                              key_bundle["identity_key"],
                                                              key_bundle["signed_pre_key"],
                                                              key_bundle["signed_pre_key_signature"],
                                                              key_bundle["one_time_pre_key"]):
                                print(f"Saved keys for {user} to database")
                                await websocket.send(self.CMS.payload("ok", "keys_ok"))
                            else:
                                print(f"Error while saving keys for {user}")
                                await websocket.send(self.CMS.payload("error", "keys_fail"))

                        else:
                            print(f"Unknown command '{response}' from {websocket.remote_address}")
                            await websocket.send(self.CMS.payload("error", "Unknown command"))
                else:
                    print(f"Unknown command '{command}' from {websocket.remote_address}")
                    await websocket.send(self.CMS.payload("error", "Unknown command"))

        except websockets.exceptions.ConnectionClosed:
            print(f"Connection from {websocket.remote_address} closed during authentication.")
        except json.JSONDecodeError:
            print(f"Error decoding JSON from {websocket.remote_address}")
        except Exception as e:
            print(f"Error in connection_handler for {websocket.remote_address}: {e}")
        finally:
            if not authenticated_and_handled:
                await websocket.close()
                return False

