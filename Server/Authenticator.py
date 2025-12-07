from __future__ import annotations
import threading
from typing import Any, Coroutine

import websockets
import json
import asyncio
from Server import caching
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from database import StorageManager

class AuthenticatorAndKeyHandler:
    """
    Handles user authentication and cryptographic key management for the secure
    chat server.

    This class is responsible for processing login and registration requests,
    verifying user credentials using the Argon2 password hashing algorithm,
    and storing and retrieving user key bundles from the database. It acts as
    the gatekeeper for client connections, ensuring that only authenticated
    users can proceed to the main application.
    """
    def __init__(self, caching: caching.caching,
                 storage_manager: StorageManager.StorageManager) -> None:
        """
        Initializes the authenticator.

        Args:
            caching: The cache management system instance.
            storage_manager: The key storage instance.
        """
        self.caching = caching
        self.StorageManager = storage_manager
        self.ph = PasswordHasher()

    async def handle_authentication(self, websocket) -> str | None:
        """
        Handles the authentication process for a new client connection.

        This method listens for 'login' or 'register' commands from the client,
        verifies credentials, handles registration including key publishing,
        and adds the user to the active user cache upon successful
        authentication.

        Args:
            websocket: The WebSocket connection object for the client.

        Returns:
            The user_id of the authenticated user, or None if authentication
            fails or the connection is closed.
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
                    
                    stored_hash = self.StorageManager.GetUserPasswordHash(user)

                    if not stored_hash:
                        await websocket.send(self.caching.payload("error", "Credfail"))
                        continue

                    try:
                        self.ph.verify(stored_hash, passw)
                        session_token = self.caching.create_session_token(user)
                        payload = {
                            "text": "success",
                            "session_token": session_token
                        }
                        await websocket.send(self.caching.payload("ok", payload))
                        authenticated_and_handled = True
                        self.caching.add_active_user(websocket, user, None)
                        return user
                    except VerifyMismatchError:
                        await websocket.send(self.caching.payload("error", "Credfail"))
                        continue
                
                elif command == "token_login":
                    token = payload.get("token")
                    user = self.caching.validate_session_token(token)

                    if user:
                        await websocket.send(self.caching.payload("ok", {
                            "text": "success",
                            "session_token": token
                        }))
                        authenticated_and_handled = True
                        self.caching.add_active_user(websocket, user, None)
                        return user
                    else:
                        await websocket.send(self.caching.payload("error", "Invalid or Expired Session Token"))
                        continue

                elif command == "register":
                    cred = payload.get("credentials", {})
                    user = cred.get("username")
                    passw = cred.get("password")

                    if not user or not passw:
                        await websocket.send(self.caching.payload("error", "Invalid format"))
                        continue

                    if self.StorageManager.UserExists(user):
                        await websocket.send(self.caching.payload("error", "AAE"))
                        continue
                    else:
                        hashed_password = self.ph.hash(passw)
                        if self.StorageManager.InsertUser(user, hashed_password):
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
                return None