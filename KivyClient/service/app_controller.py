import json
import asyncio
from kivy.event import EventDispatcher
from kivy.clock import Clock
from kivy.app import App
from KivyClient.service.network_service import NetworkService
from KivyClient.service.crypt_services import CryptServices


class AppController(EventDispatcher):
    """
    The main controller for the Kivy client application.

    It mediates between the NetworkService, CryptServices, and the Kivy GUI (accessed via App).
    """

    def __init__(self):
        super().__init__()
        self.username = None
        self.current_state = "Login"
        self.public_bundle = None
        self.pending_messages = {}

        # Initialize services
        self.network = NetworkService()
        self.crypt_services = None

        # Connect network events
        self.connect_network_signals()

    def get_app(self):
        """Helper to get the running Kivy App instance safely."""
        return App.get_running_app()

    def run(self):
        """Starts the network services."""
        self.network.start()
        self.network.connect()

    def connect_network_signals(self):
        """Binds NetworkService events to controller methods."""
        self.network.bind(on_connected=self.on_network_connected)
        self.network.bind(on_disconnected=self.on_network_disconnected)
        self.network.bind(on_message_received=self.handle_network_message)
        self.network.bind(on_error_occurred=self.on_network_error)
        self.network.bind(on_reconnecting=self.on_network_reconnecting)

    # --- Network Event Handlers (Called from Network Thread) ---

    def on_network_connected(self, *args):
        """Handle connection established."""
        if self.network.session_token:
            # Auto-login with token
            self.network.send_payload(json.dumps({
                "command": "token_login",
                "token": self.network.session_token
            }))
        else:
            # Enable login UI
            Clock.schedule_once(lambda dt: self.get_app().enable_login_buttons())

    def on_network_disconnected(self, *args):
        """Handle disconnection."""
        Clock.schedule_once(lambda dt: self.get_app().set_status("Disconnected", "error"))

    def on_network_reconnecting(self, *args):
        """Handle reconnection attempts."""
        Clock.schedule_once(lambda dt: self.get_app().set_status("Reconnecting...", "info"))

    def on_network_error(self, instance, error):
        """Handle network errors."""
        Clock.schedule_once(lambda dt: self.get_app().set_status(f"Error: {error}", "error"))

    def handle_network_message(self, instance, payload):
        """
        Central handler for incoming server messages.
        Dispatches logic based on the 'status' field.
        """
        status = payload.get("status")
        message = payload.get("message")

        # --- Authentication & Registration ---
        if status == "ok":
            if message == "success" or (isinstance(message, dict) and message.get("text") == "success"):
                if isinstance(message, dict) and "session_token" in message:
                    self.network.set_session_token(message["session_token"])
                Clock.schedule_once(lambda dt: self.on_login_success())

            elif message == "Registration Successful":
                Clock.schedule_once(lambda dt: self.get_app().set_status("Registered! Publishing keys...", "info"))
                self.network.schedule_task(self.handle_publish_keys())

            elif message == "keys_ok":
                Clock.schedule_once(lambda dt: self.get_app().set_status("Keys published! You can log in.", "success"))

        elif status == "error":
            Clock.schedule_once(lambda dt: self.get_app().set_status(f"Error: {message}", "error"))
            Clock.schedule_once(lambda dt: self.get_app().enable_login_buttons())

        # --- Friend Requests ---
        elif status == "new_friend_request":
            from_user = message.get("from")
            Clock.schedule_once(lambda dt: self.get_app().add_friend_request(from_user))

        elif status == "pending_friend_requests":
            for from_user in message:
                Clock.schedule_once(lambda dt, user=from_user: self.get_app().add_friend_request(user))

        elif status == "friend_request_accepted":
            friend_username = message.get("friend_username")
            if friend_username:
                self.crypt_services.save_contacts_to_disk()
                Clock.schedule_once(lambda dt: self.get_app().add_contact(friend_username))
                self.request_bundle_for_partner(friend_username)

        # --- Messaging & Encryption ---
        elif status == "Encrypted":
            self.handle_encrypted_message(message)

        elif status == "User_Select":
            self.handle_user_select_response(message)

        elif status == "key_bundle_ok":
            self.handle_key_bundle_response(message)

        elif status == "key_bundle_fail":
            Clock.schedule_once(lambda dt: self.get_app().set_status("Could not get key bundle.", "error"))

    # --- User Actions (Called from GUI) ---

    def handle_login_request(self, username, password):
        """Initiates the login process."""
        self.username = username
        self.crypt_services = CryptServices(username)

        # Load local keys first
        if not self.crypt_services.load_keys_from_disk(password):
            self.get_app().set_status("Invalid local credentials or database error", "error")
            return

        self.network.set_credentials(username, password)
        self.get_app().set_status("Logging in...", "info")

        login_payload = {
            "command": "login",
            "credentials": {"username": username, "password": password}
        }
        self.network.send_payload(json.dumps(login_payload))

    def handle_register_request(self, username, password):
        """Initiates registration by generating keys and sending payload."""
        self.get_app().set_status("Generating Keys...", "info")
        # Run key generation in background to avoid freezing UI
        self.network.schedule_task(self.async_register(username, password))

    async def async_register(self, username, password):
        """Async wrapper for key generation and registration."""
        self.username = username
        self.crypt_services = CryptServices(username)
        try:
            # CPU-intensive key gen runs in a thread
            self.public_bundle = await asyncio.to_thread(self.crypt_services.generate_and_save_key, password)

            if self.public_bundle is None:
                Clock.schedule_once(lambda dt: self.get_app().set_status("User exists on device", "error"))
                return

            Clock.schedule_once(lambda dt: self.get_app().set_status("Registering...", "info"))
            register_payload = {
                "command": "register",
                "credentials": {"username": username, "password": password}
            }
            self.network.send_payload(json.dumps(register_payload))
        except Exception as e:
            Clock.schedule_once(lambda dt: self.get_app().set_status(str(e), "error"))

    async def handle_publish_keys(self):
        """Publishes the generated key bundle to the server."""
        if self.public_bundle:
            self.network.send_payload(json.dumps({
                "command": "publish_keys",
                "bundle": self.public_bundle
            }))
            self.public_bundle = None

    def on_login_success(self):
        """Post-login setup."""
        self.get_app().switch_to_chat()
        self.crypt_services.save_contacts_to_disk()

        # Load contacts into UI
        contacts = self.crypt_services.load_contacts_from_disk()
        for contact in contacts:
            self.get_app().add_contact(contact)

        # Check for pending requests
        self.network.send_payload(json.dumps({"command": "get_pending_friend_requests"}))

    def handle_user_select(self, partner):
        """User selected a chat partner."""
        # Load history
        history = self.crypt_services.db.get_messages(partner)
        self.get_app().load_chat_history(history, self.username)

        # Notify server
        self.network.send_payload(json.dumps({"status": "User_Select", "user_id": partner}))

    def handle_user_select_response(self, message):
        """Response from server about user availability."""
        if message in ("User Available", "User Available And Friends"):
            # Fetch their keys to be ready to encrypt
            self.request_bundle_for_partner(self.get_app().current_partner)
        elif message == "User Not Friend":
            Clock.schedule_once(lambda dt: self.get_app().set_status("User is not a friend", "error"))

    def request_bundle_for_partner(self, partner):
        self.network.send_payload(json.dumps({"status": "request_key_bundle", "user_id": partner}))

    def handle_key_bundle_response(self, message):
        """Received a public key bundle."""
        partner = message.get("user_id")
        if partner and partner != self.username:
            self.crypt_services.store_partner_bundle(partner, message)

            # If we had messages waiting for this bundle, process them now
            if partner in self.pending_messages:
                self.network.loop.call_soon_threadsafe(self.process_pending_message, partner)

    def send_message(self, partner, text):
        """Encrypts and sends a message."""
        if partner not in self.crypt_services.partner_bundles:
            # We don't have keys yet, try to fetch them
            self.get_app().set_status("Fetching keys... try again in a second", "info")
            self.request_bundle_for_partner(partner)
            return

        encrypted_payload = self.crypt_services.encrypt_message(partner, text)

        # Save to local DB
        self.crypt_services.db.add_message(partner, self.username, text)
        # Update UI
        self.get_app().add_message("Me", text)

        server_payload = {
            "status": "Encrypted",
            "message": {
                "text": encrypted_payload,
                "sender_user_id": self.username,
                "recv_user_id": partner
            }
        }
        self.network.send_payload(json.dumps(server_payload))

    def handle_encrypted_message(self, message):
        """Decrypts and displays an incoming message."""
        sender = message.get("sender_user_id")
        if sender != self.username:
            encrypted_payload = message.get("text")

            # Attempt decryption
            result = self.crypt_services.decrypt_message(sender, encrypted_payload)

            if result == "NEEDS_BUNDLE":
                # We need the sender's keys to establish session
                self.pending_messages[sender] = encrypted_payload
                self.request_bundle_for_partner(sender)
            elif result:
                # Decryption success
                self.crypt_services.db.add_message(sender, sender, result)

                # Only update UI if we are currently looking at this chat
                def update_ui(dt):
                    if self.get_app().current_partner == sender:
                        self.get_app().add_message(sender, result)

                Clock.schedule_once(update_ui)

    def process_pending_message(self, partner):
        """Retry decrypting a cached message now that we have keys."""
        encrypted = self.pending_messages.pop(partner, None)
        if encrypted:
            result = self.crypt_services.decrypt_message(partner, encrypted)
            if result and result != "NEEDS_BUNDLE":
                self.crypt_services.db.add_message(partner, partner, result)

                def update_ui(dt):
                    if self.get_app().current_partner == partner:
                        self.get_app().add_message(partner, result)

                Clock.schedule_once(update_ui)

    def send_friend_request(self, friend_username):
        if friend_username:
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
        # Remove request from UI
        Clock.schedule_once(lambda dt: self.get_app().remove_friend_request(from_user))

    def logout(self):
        self.network.logout()
        self.username = None
        self.get_app().switch_to_login()