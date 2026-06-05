import json
import asyncio
import os
import traceback
from os.path import exists

from flet import StoragePaths
import httpx

from services.network_service import NetworkService
from services.crypt_services import CryptServices


class AppController:
    def __init__(self, page, page_update_callback, status_callback, use_local=True):
        self.page = page
        self.update_ui = page_update_callback
        self.set_status = status_callback

        self.username = None
        self.public_bundle = None
        self.pending_messages = {}
        self.current_partner = None

        self.network = NetworkService(use_local)
        self.crypt_services = None

        self._temp_register_username = None
        self._temp_register_password = None
        self._session_file_path = None

        self.connect_network_signals()

    def run(self):
        try:
            self.page.run_task(self._startup_async)
        except Exception as e:
            print(f"Failed to start app controller: {e}")

    async def _get_session_file_path(self):
        if self._session_file_path:
            return self._session_file_path

        storage_paths = StoragePaths()
        support_dir = await storage_paths.get_application_support_directory()
        app_dir = os.path.join(support_dir, "texter_e2ee")
        os.makedirs(app_dir, exist_ok=True)
        self._session_file_path = os.path.join(app_dir, "session.json")
        return self._session_file_path

    async def _load_saved_session(self):
        session_file = await self._get_session_file_path()
        if not os.path.exists(session_file):
            return None

        try:
            with open(session_file, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            token = payload.get("session_token")
            username = payload.get("username")
            if token and username:
                return token, username
        except Exception as e:
            print(f"Could not load saved session: {e}")
        return None

    async def _save_session_to_storage(self, token: str, username: str):
        session_file = await self._get_session_file_path()
        try:
            with open(session_file, "w", encoding="utf-8") as handle:
                json.dump({"session_token": token, "username": username}, handle)
        except Exception as e:
            print(f"Could not save session to storage: {e}")

    async def _clear_session_storage(self):
        session_file = await self._get_session_file_path()
        try:
            if os.path.exists(session_file):
                os.remove(session_file)
        except Exception as e:
            print(f"Could not remove session from storage: {e}")

    async def _startup_async(self):
        saved_session = await self._load_saved_session()
        self.network.start()

        if saved_session:
            saved_token, saved_username = saved_session
            print(f"Found saved session for {saved_username}")
            self.username = saved_username
            self.network.set_session_token(saved_token)

            # Initialize crypt services since we are skipping the password screen
            self.crypt_services = CryptServices(saved_username)
            self.crypt_services.load_database_without_password()

            self.network.connect()
        else:
            self.update_ui("ENABLE_LOGIN")
            self.set_status("Ready. Please log in or register.", "info")

    def handle_lifecycle_change(self, state: str):
        """Handle Flet app lifecycle changes (resumed, paused, etc.)"""
        print(f"App lifecycle changed: {state}")
        if state == "resumed":
            if not self.network.is_connected and self.network.session_token:
                self.set_status("App resumed, reconnecting...", "info")
                self.network.connect()

    def connect_network_signals(self):
        self.network.bind('on_connected', self.on_network_connected)
        self.network.bind('on_disconnected', self.on_network_disconnected)
        self.network.bind('on_message_received', self.handle_network_message)
        self.network.bind('on_error_occurred', self.on_network_error)
        self.network.bind('on_reconnecting', self.on_network_reconnecting)
        self.network.bind('on_auth_failed', self.logout)

    def on_network_connected(self):
        # If we have a token (auto-login), use it.
        # If NOT (logout state), enable the buttons.
        if self.network.session_token:
            self.on_login_success()
        else:
            self.update_ui("ENABLE_LOGIN")

    def on_network_disconnected(self):
        self.set_status("Disconnected", "error")
        self.update_ui("ENABLE_LOGIN")

    def on_network_reconnecting(self):
        self.set_status("Reconnecting...", "info")

    def on_network_error(self, error):
        self.set_status(f"Net Error: {error}", "error")
        self.update_ui("ENABLE_LOGIN")

    def handle_network_message(self, payload):
        try:
            status = payload.get("status")
            message = payload.get("message")

            if status == "new_friend_request":
                from_user = message.get("from")
                self.update_ui("ADD_REQUEST", from_user)

            elif status == "pending_friend_requests":
                for from_user in message:
                    self.update_ui("ADD_REQUEST", from_user)

            elif status == "friend_request_accepted":
                friend_username = message.get("friend_username")
                if friend_username:
                    if self.crypt_services:
                        self.crypt_services.save_contacts_to_disk()
                    self.update_ui("ADD_CONTACT", friend_username)
                    self.update_ui("REMOVE_SENT_REQUEST", friend_username)
                    self.request_bundle_for_partner(friend_username)

            elif status == "Encrypted":
                self.handle_encrypted_message(message)

            elif status == "User_Select":
                if message in ("User Available", "User Available And Friends"):
                    self.request_bundle_for_partner(self.current_partner)
                elif message == "User Not Friend":
                    self.set_status("User is not a friend", "error")

            elif status == "key_bundle_ok":
                self.handle_key_bundle_response(message)

            elif status == "key_bundle_fail":
                self.set_status("Could not get key bundle", "error")

            elif status == "user_existence_status":
                if message == "User_Exists":
                    self.set_status("Username already exists", "error")
                    self._temp_register_password = None
                elif message == "User_Not_Exists":
                    self.set_status("Username available. Generating keys...", "info")
                    self.network.schedule_task(
                        self.async_register(
                            self._temp_register_username,
                            self._temp_register_password
                        )
                    )

        except Exception as e:
            err_msg = f"Logic Error: {str(e)}"
            print(traceback.format_exc())
            self.set_status(err_msg, "error")

    def handle_login_request(self, username, password):
        try:
            self.username = username
            self.crypt_services = CryptServices(username)

            if not self.crypt_services.load_keys_from_disk(password):
                self.set_status("Invalid credentials or DB corrupt", "error")
                return

            self.page.run_task(self.async_login, username, password)
        except Exception as e:
            self.set_status(f"Login failed: {str(e)}", "error")

    async def async_login(self, username, password):
        self.set_status("Logging in...", "info")
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.network.auth_url}/api/auth/login",
                    json={"username": username, "password": password}
                )

            if resp.status_code == 200:
                resp_json = resp.json()
                token = resp_json.get("access_token")
                
                if not token:
                    self.set_status("Login failed: Received empty token from server", "error")
                    self.update_ui("ENABLE_LOGIN")
                    return

                self.network.set_session_token(token)
                await self._save_session_to_storage(token, username)
                self.set_status("Authentication successful, connecting to server...", "info")
                self.network.connect() 
            else:
                self.set_status("Login failed: Invalid credentials", "error")
                self.update_ui("ENABLE_LOGIN")
        
        except Exception as e:
            self.set_status(f"Auth Network Error: {str(e)}", "error")
            self.update_ui("ENABLE_LOGIN")


    def handle_register_request(self, username, password):
        self.page.run_task(self.async_register, username, password)

    async def async_register(self, username, password):
        try:
            self.set_status("Generating Encryption Keys...", "info")
            self.username = username
            self.crypt_services = CryptServices(username)

            self.publish_bundle = await asyncio.to_thread(
                self.crypt_services.generate_and_save_key, 
                password,
                True
            )
            if self.publish_bundle is None:
                self.set_status("Key generation failed", "error")
                return
            
            self.set_status("Registering with server...", "info")

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.network.auth_url}/api/auth/register",
                    json={
                        "username": username, 
                        "password": password,
                        "key_bundle": self.publish_bundle}
                )
            
            if resp.status_code == 201:
                self.set_status("Registration successful! Keys Published!", "success")
                await self.async_login(username, password)
            
            elif resp.status_code == 409:
                self.set_status("Username already exists", "error")
            
            else:
                self.set_status(f"Registration failed: {resp.text}", "error")

        except Exception as e:
            self.set_status(f"Reg Error: {str(e)}", "error")

    def on_login_success(self):
        if self.crypt_services:
            self.crypt_services.save_contacts_to_disk()
            contacts = self.crypt_services.load_contacts_from_disk()
            for contact in contacts:
                self.update_ui("ADD_CONTACT", contact)

        self.network.send_payload(json.dumps({"command": "get_pending_friend_requests"}))
        self.update_ui("SWITCH_TO_CHAT")
        self.set_status(f"Connected as {self.username}", "success")

    def handle_user_select(self, partner):
        self.current_partner = partner
        if self.crypt_services:
            history = self.crypt_services.db.get_messages(partner)
            self.update_ui("LOAD_HISTORY", (history, self.username))
        self.network.send_payload(json.dumps({"status": "User_Select", "user_id": partner}))

    def send_message(self, text):
        partner = self.current_partner
        if not partner:
            self.set_status("Select a contact first!", "error")
            return

        if not self.username:
            self.set_status("Not logged in", "error")
            return

        if not self.crypt_services:
            self.set_status("Encryption service not ready", "error")
            return

        if partner not in self.crypt_services.partner_bundles:
            self.set_status(f"Fetching keys for {partner}...", "info")
            self.request_bundle_for_partner(partner)
            return

        try:
            encrypted_payload = self.crypt_services.encrypt_message(partner, text)
            self.crypt_services.db.add_message(partner, self.username, text)
            self.update_ui("ADD_MESSAGE", ("Me", text))

            self.network.send_payload(json.dumps({
                "status": "Encrypted",
                "message": {
                    "text": encrypted_payload,
                    "sender_user_id": self.username,
                    "recv_user_id": partner
                }
            }))
        except Exception as e:
            self.set_status(f"Send Error: {e}", "error")

    def handle_encrypted_message(self, message):
        sender = message.get("sender_user_id")
        if sender != self.username and self.crypt_services:
            encrypted_payload = message.get("text")
            result = self.crypt_services.decrypt_message(sender, encrypted_payload)

            if result == "NEEDS_BUNDLE":
                self.pending_messages[sender] = encrypted_payload
                self.request_bundle_for_partner(sender)
                self.set_status(f"Fetching keys for {sender}...", "info")
            elif result:
                self.crypt_services.db.add_message(sender, sender, result)
                if self.current_partner == sender:
                    self.update_ui("ADD_MESSAGE", (sender, result))
                else:
                    self.set_status(f"New message from {sender}", "success")
            else:
                self.set_status(f"Decryption failed from {sender}", "error")

    def request_bundle_for_partner(self, partner):
        self.network.send_payload(json.dumps({"status": "request_key_bundle", "user_id": partner}))

    def handle_key_bundle_response(self, message):
        partner = message.get("user_id")
        if partner and partner != self.username and self.crypt_services:
            self.crypt_services.store_partner_bundle(partner, message)
            self.set_status(f"Keys obtained for {partner}. Try sending now.", "success")
            
            if partner in self.pending_messages:
                encrypted_payload = self.pending_messages.pop(partner)
                result = self.crypt_services.decrypt_message(partner, encrypted_payload)
                if result and result != "NEEDS_BUNDLE":
                    self.crypt_services.db.add_message(partner, partner, result)
                    if self.current_partner == partner:
                        self.update_ui("ADD_MESSAGE", (partner, result))
                    else:
                        self.set_status(f"New message from {partner}", "success")

    def send_friend_request(self, friend_username):
        if friend_username:
            self.update_ui("ADD_SENT_REQUEST", friend_username)
            self.network.send_payload(json.dumps({
                "command": "friend_request",
                "from_user": self.username,
                "to_user": friend_username
            }))

    def accept_friend_request(self, from_user):
        self.network.send_payload(json.dumps({
            "command": "accept_friend_request",
            "from_user": from_user,
            "to_user": self.username
        }))
        self.update_ui("REMOVE_REQUEST", from_user)

    def logout(self):
        # 1. Clear persistent storage
        try:
            self.page.run_task(self._clear_session_storage)
        except Exception as e:
            print(f"Could not remove session from storage: {e}")

        # 2. Logout from network (closes socket)
        self.network.logout()

        # 3. Clear local state
        self.username = None
        self.current_partner = None
        self.crypt_services = None

        # 4. Switch to login screen
        self.update_ui("SWITCH_TO_LOGIN")
        self.update_ui("ENABLE_LOGIN")
        self.set_status("Logged out successfully", "info")
