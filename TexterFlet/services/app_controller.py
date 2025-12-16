import json
import asyncio
import traceback
from os.path import exists

from services.network_service import NetworkService
from services.crypt_services import CryptServices


class AppController:
    # 1. Update __init__ to accept 'page'
    def __init__(self, page, page_update_callback, status_callback):
        self.page = page  # Store page reference for client_storage
        self.update_ui = page_update_callback
        self.set_status = status_callback

        self.username = None
        self.public_bundle = None
        self.pending_messages = {}
        self.current_partner = None

        self.network = NetworkService()
        self.crypt_services = None

        self._temp_register_username = None
        self._temp_register_password = None

        self.connect_network_signals()

    def run(self):
        # 2. Check for saved token on startup
        saved_token = self.page.client_storage.get("session_token")
        saved_username = self.page.client_storage.get("username")

        if saved_token and saved_username:
            print(f"Found saved session for {saved_username}")
            self.username = saved_username
            self.network.set_session_token(saved_token)

            # Initialize crypt services since we are skipping the password screen
            self.crypt_services = CryptServices(saved_username)
            # Note: You might need to handle loading keys securely here if they are password protected.
            # For this example, we assume keys are accessible or handled by the token flow.

        self.network.start()
        self.network.connect()

    def connect_network_signals(self):
        self.network.bind('on_connected', self.on_network_connected)
        self.network.bind('on_disconnected', self.on_network_disconnected)
        self.network.bind('on_message_received', self.handle_network_message)
        self.network.bind('on_error_occurred', self.on_network_error)
        self.network.bind('on_reconnecting', self.on_network_reconnecting)

    def on_network_connected(self):
        # If we loaded a token in run(), this will auto-login
        if self.network.session_token:
            self.set_status(f"Resuming session as {self.username}...", "info")
            self.network.send_payload(json.dumps({
                "command": "token_login",
                "token": self.network.session_token
            }))
        else:
            self.update_ui("ENABLE_LOGIN")

    def on_network_disconnected(self):
        self.set_status("Disconnected", "error")

    def on_network_reconnecting(self):
        self.set_status("Reconnecting...", "info")

    def on_network_error(self, error):
        self.set_status(f"Net Error: {error}", "error")

    def handle_network_message(self, payload):
        try:
            status = payload.get("status")
            message = payload.get("message")

            if status == "ok":
                if message == "success" or (isinstance(message, dict) and message.get("text") == "success"):
                    # 3. Save token on successful login
                    if isinstance(message, dict) and "session_token" in message:
                        token = message["session_token"]
                        self.network.set_session_token(token)

                        # SAVE TO STORAGE
                        self.page.client_storage.set("session_token", token)
                        self.page.client_storage.set("username", self.username)

                    self.on_login_success()

                elif message == "Registration Successful":
                    self.set_status("Registered! Publishing keys...", "info")
                    self.network.schedule_task(self.handle_publish_keys())

                elif message == "keys_ok":
                    self.set_status("Keys published! You can log in.", "success")

            elif status == "error":
                # If token is invalid (expired), clear storage and ask for login
                if "Invalid token" in str(message):
                    self.logout()

                self.set_status(f"Server Error: {message}", "error")
                self.update_ui("ENABLE_LOGIN")

            elif status == "new_friend_request":
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

            self.network.set_credentials(username, password)
            self.set_status("Logging in...", "info")

            if self.network.is_connected:
                self.network.send_payload(json.dumps({
                    "command": "login",
                    "credentials": {"username": username, "password": password}
                }))
            else:
                self.network.connect()

        except Exception as e:
            self.set_status(f"Login failed: {str(e)}", "error")

    def handle_register_request(self, username, password):
        self._temp_register_password = password
        self._temp_register_username = username

        self.set_status("Checking Avaibility...", "info")
        self.network.send_payload(json.dumps({
            "command": "check_user_existence",
            "username": username
        }))

    async def async_register(self, username, password):
        try:
            self.username = username
            self.crypt_services = CryptServices(username)
            self.public_bundle = await asyncio.to_thread(
                self.crypt_services.generate_and_save_key,
                password,
                True
            )
            if self.public_bundle is None:
                self.set_status("Failure in Key generation", "error")
                return

            self.set_status("Registering...", "info")
            self.network.send_payload(json.dumps({
                "command": "register",
                "credentials": {"username": username, "password": password}
            }))
            self._temp_register_password = None
            self._temp_register_username = None

        except Exception as e:
            self.set_status(f"Reg Error: {str(e)}", "error")

    async def handle_publish_keys(self):
        if self.public_bundle:
            self.network.send_payload(json.dumps({
                "command": "publish_keys",
                "bundle": self.public_bundle
            }))
            self.public_bundle = None

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
        # 4. Clear storage on logout
        self.page.client_storage.remove("session_token")
        self.page.client_storage.remove("username")

        self.network.logout()
        self.username = None
        self.current_partner = None
        self.update_ui("SWITCH_TO_LOGIN")