from __future__ import annotations
import threading
from typing import Any, Coroutine

import websockets
import json
import asyncio
from NewServerCode import caching
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from database import StorageManager

class AuthenticatorAndKeyHandler:
    def __init__(self, caching: caching.caching,
                 storage_manager: StorageManager.StorageManager) -> None:
        """
        Initializes the authenticator.
        :param caching: The cache management system instance
        :param storage_manager: The key storage instance
        """
        self.caching = caching
        self.StorageManager = storage_manager
        self.ph = PasswordHasher()

    async def handle_authentication(self, websocket) -> str | None:
        """
        Handle the authentication of the client.
        Returns the user_id on successful authentication, otherwise None.
        """
        authenticated_and_handled = False
        tries=0
        try:
            while not authenticated_and_handled and tries<5:
                tries += 1
                payload_str = await websocket.recv()
                payload = json.loads(payload_str)
                command = payload.get("command")

                if command == "login":
                    cred = payload.get("credentials", {})
                    user = cred.get("username")
                    passw = cred.get("password")

                    if not user or not passw:
                        await websocket.send(self.caching.payload("error", "Invalid format"))
                        continue
                    
                    # 1. Fetch the stored hash from the database
                    stored_hash = self.StorageManager.GetUserPasswordHash(user) # You will need to implement this method

                    if not stored_hash:
                        await websocket.send(self.caching.payload("error", "Credfail")) # User not found
                        continue

                    # 2. Verify the password against the hash
                    try:
                        self.ph.verify(stored_hash, passw)
                        # If verify() succeeds, the password is correct.
                        await websocket.send(self.caching.payload("ok", "success"))
                        authenticated_and_handled = True
                        self.caching.add_active_user(websocket, user, None)
                        return user  # Return user_id on success
                    except VerifyMismatchError:
                        # This is the expected error for a wrong password.
                        await websocket.send(self.caching.payload("error", "Credfail"))
                        continue

                elif command == "register":
                    cred = payload.get("credentials", {})
                    user = cred.get("username")
                    passw = cred.get("password")

                    if not user or not passw:
                        await websocket.send(self.caching.payload("error", "Invalid format"))
                        continue

                    # Check if user already exists
                    if self.StorageManager.UserExists(user): # You will need to implement this method
                        await websocket.send(self.caching.payload("error", "AAE"))
                        continue
                    else:
                        # 1. Hash the new password
                        hashed_password = self.ph.hash(passw)
                        # 2. Store the user and the HASHED password
                        if self.StorageManager.InsertUser(user, hashed_password): # You will need to implement this method
                            await websocket.send(self.caching.payload("ok", "Registration Successful"))

                            response_payload = await websocket.recv()
                            response = json.loads(response_payload)
                            if response.get("command") == "publish_keys":
                                key_bundle = response.get("bundle")
                                if self.StorageManager.SaveKeyBundle(key_bundle, user):
                                    await websocket.send(self.caching.payload("ok", "keys_ok"))
                                else:
                                    await websocket.send(self.caching.payload("error", "keys_fail"))
                            else:
                                await websocket.send(self.caching.payload("error", "Unknown command"))
                        else:
                            await websocket.send(self.caching.payload("error", "Registration failed on server."))
                        continue

                else:
                    await websocket.send(self.caching.payload("error", "Unknown command"))
                    continue

            return None

        except (websockets.exceptions.ConnectionClosed, websockets.exceptions.ConnectionClosedError, websockets.exceptions.ConnectionClosedOK):
            print(f"Connection from {websocket.remote_address} closed during authentication.")
        except json.JSONDecodeError:
            print(f"Error decoding JSON from {websocket.remote_address}")
        except Exception as e:
            print(f"Error in connection_handler for {websocket.remote_address}: {e}")
        finally:
            if not authenticated_and_handled or tries>=5:
                # This block now only runs on exceptions or graceful client disconnect
                return None