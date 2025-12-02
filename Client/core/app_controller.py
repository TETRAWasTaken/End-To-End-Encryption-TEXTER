import json

from PySide6.QtCore import QObject, Slot, Signal
import asyncio
from Client.gui.login_window import LoginWindow
from Client.gui.chat_window import ChatWindow
from Client.services.network_service import NetworkService
from Client.services.crypt_services import CryptServices

class AppController(QObject):
    def __init__(self):
        super().__init__()

        # State
        self.username = None
        self.current_state = "Login"
        self.public_bundle = None
        self.pending_messages = {} # Cache for messages waiting for a bundle

        # Create Services
        self.network = NetworkService()

        # Create GUI
        self.login_view = LoginWindow()
        self.chat_view = None
        self.crypt_services = None

        # Connect Signals
        self.connect_network_signals()
        self.connect_login_signals()

    def run(self):
        """
        Starts the Application
        """
        self.login_view.show()
        self.network.start()  # Start the background thread
        self.network.connect()  # Schedule the connection

    # Mapping the signals

    def connect_network_signals(self):
        self.network.connected.connect(self.on_network_connected)
        self.network.disconnected.connect(self.on_network_disconnected)
        self.network.message_received.connect(self.handle_network_message)
        self.network.error_occured.connect(self.on_network_error)

    def connect_login_signals(self):
        self.login_view.login_requested.connect(self.handle_login_request)
        self.login_view.registration_requested.connect(self.handle_register_request)

    def connect_chat_signals(self):
        if self.chat_view:
            self.chat_view.send_message_requested.connect(self.handle_send_message)
            self.chat_view.partner_selected.connect(self.handle_partner_select)
            self.chat_view.friend_request_sent.connect(self.handle_friend_request)
            self.chat_view.friend_request_accepted.connect(self.handle_friend_request_accepted)

    # Slots

    @Slot()
    def on_network_connected(self):
        self.login_view.enable_buttons()

    @Slot()
    def on_network_disconnected(self):
        view = self.chat_view if self.chat_view and self.chat_view.isVisible() else self.login_view
        if hasattr(view, 'set_status'):
            view.set_status("Disconnected", "red")
        if hasattr(view, 'disable_buttons'):
            view.disable_buttons()

    @Slot(str)
    def on_network_error(self, err_message):
        view = self.chat_view if self.chat_view and self.chat_view.isVisible() else self.login_view
        if hasattr(view, 'set_status'):
            view.set_status(f"Error : {err_message}", "red")

    @Slot(dict)
    def handle_network_message(self, payload: dict):
        """
        Handles all the incoming payload from the server
        """
        status = payload.get("status")
        message = payload.get("message")

        if self.current_state in ("login", "register", "register_keys"):
            view = self.login_view
        else:
            view = self.chat_view

        if status == "ok":
            if message == "success":  # Login OK
                self.current_state = "chat"
                self.on_login_success()
            elif message == "Registration Successful":
                view.set_status("Registered! Publishing keys...", "blue")
                self.current_state = "register_keys"
                self.network.schedule_task(self.handle_publish_keys())
            elif message == "keys_ok":
                view.set_status("Keys published! You can log in.", "green")
                self.current_state = "login"

        elif status == "error":
            view.set_status(f"Error: {message}", "red")

        elif status == "new_friend_request":
            if self.chat_view:
                from_user = message.get("from")
                self.chat_view.add_friend_request_notification(from_user)

        elif status == "friend_request_status":
            if self.chat_view:
                self.chat_view.show_friend_request_status(message)

        elif status == "pending_friend_requests":
            if self.chat_view:
                for from_user in message:
                    self.chat_view.add_friend_request_notification(from_user)

        elif status == "Encrypted":
            if self.chat_view:
                sender = message.get("sender_user_id")
                if sender != self.username:
                    encrypted_payload = message.get("text")
                    
                    decryption_result = self.crypt_services.decrypt_message(sender, encrypted_payload)

                    if decryption_result == "NEEDS_BUNDLE":
                        # Cache the message and request the bundle
                        self.pending_messages[sender] = encrypted_payload
                        self.request_bundle_for_partner(sender)
                    elif decryption_result is not None:
                        self.crypt_services.db.add_message(sender, sender, decryption_result)
                        if self.chat_view.current_partner == sender:
                            self.chat_view.add_message(sender, decryption_result)


            else:
                print("Received chat message but no chat view is active.")

        elif status == "User_Select":
            if message == "User Available":
                if self.chat_view:
                    self.chat_view.set_status("User is available, fetching keys...", "blue")
                    self.request_bundle_for_partner(self.chat_view.current_partner)

            elif message == "User Not Online":
                if self.chat_view:
                    self.chat_view.set_status("User is offline. They will receive the message upon login.", "orange")
                    self.request_bundle_for_partner(self.chat_view.current_partner)

            elif message == "User Not Available":
                if self.chat_view:
                    self.chat_view.set_status("User not available", "red")
                    self.chat_view.set_input_enabled(False)
            
            elif message == "User Not Friend":
                if self.chat_view:
                    self.chat_view.set_status("You can only chat with friends.", "red")
                    self.chat_view.set_input_enabled(False)


        elif status == "key_bundle_ok":
            partner_username = message.get("user_id")
            if partner_username and self.crypt_services and partner_username != self.username:
                self.crypt_services.store_partner_bundle(partner_username, message)

                if self.chat_view and self.chat_view.current_partner == partner_username:
                    self.chat_view.set_status(f"Ready to chat with {partner_username}", "green")
                    self.chat_view.set_input_enabled(True)
                
                    # If there's a pending message, schedule it for processing
                    if partner_username in self.pending_messages:
                        # FIX: Use self.network.loop instead of asyncio directly
                        self.network.loop.call_soon_threadsafe(self.process_pending_message, partner_username)


        elif status == "key_bundle_fail":
            if self.chat_view:
                if message == "not_friends":
                    self.chat_view.set_status("Cannot start a secure session. You are not friends with this user.", "red")
                else:
                    self.chat_view.set_status("Selected partner cannot be contacted", "red")
                self.chat_view.set_input_enabled(False)



    # Slots for GUI Signals
    @Slot(str, str)
    def handle_login_request(self, username: str, password: str):
        self.username = username
        self.login_view.set_status("Loading keys...", "blue")
        self.crypt_services = CryptServices(username)

        if not self.crypt_services.load_keys_from_disk(password):
            self.login_view.set_status("Invalid credentials", "red")
            self.current_state = "login"
            return

        self.login_view.set_status("Logging in...", "blue")
        self.current_state = "login"

        login_payload = {
            "command": "login",
            "credentials": {"username": username, "password": password}
        }
        self.network.send_payload(json.dumps(login_payload))

    @Slot(str, str)
    def handle_register_request(self, username: str, password: str):
        self.login_view.set_status("Generating Keys...", "blue")
        self.network.schedule_task(self.async_register(username, password))

    @Slot(str)
    def handle_friend_request(self, friend_username: str):
        payload = {
            "command": "friend_request",
            "from_user": self.username,
            "to_user": friend_username
        }
        self.network.send_payload(json.dumps(payload))

    @Slot(str)
    def handle_friend_request_accepted(self, from_user: str):
        payload = {
            "command": "accept_friend_request",
            "from_user": from_user,
            "to_user": self.username
        }
        self.network.send_payload(json.dumps(payload))

    async def async_register(self, username: str, password: str):
        self.username = username
        self.crypt_services = CryptServices(username)

        try:
            self.public_bundle = await asyncio.to_thread(
                self.crypt_services.generate_and_save_key, password
            )
            if self.public_bundle is None:
                self.login_view.set_status("Username already exists on this device.", "red")
                return

            self.login_view.set_status("Registering...", "blue")
            self.current_state = "register"
            register_payload = {
                "command": "register",
                "credentials": {"username": username, "password": password}
            }
            self.network.send_payload(json.dumps(register_payload))

        except Exception as e:
            self.login_view.set_status(f"Error in register_request: {str(e)}", "red")

    async def handle_publish_keys(self):
        """
        Called by handle_network_message after registration succesful
        """
        if self.public_bundle:
            payload = {
                "command": "publish_keys",
                "bundle": self.public_bundle
            }
            self.network.send_payload(json.dumps(payload))
            self.public_bundle = None
        else:
            print("Error: Public key bundle not found.")

    @Slot(str, str)
    def handle_send_message(self, partner: str, text: str):
        """
        Encrypts and sends a message. The check here is for the partner bundle,
        as the session for the initiator is created lazily inside encrypt_message.
        """
        if partner not in self.crypt_services.partner_bundles:
            self.chat_view.set_status(f"Cannot send message. No key bundle for {partner}. Please re-select them.", "red")
            return

        encrypted_payload = self.crypt_services.encrypt_message(partner, text)
        
        self.crypt_services.db.add_message(partner, self.username, text)

        server_payload = {
            "status": "Encrypted",
            "message": {
                "text": encrypted_payload,
                "sender_user_id": self.username,
                "recv_user_id": partner
            }
        }
        self.network.send_payload(json.dumps(server_payload))

    @Slot(str)
    def handle_partner_select(self, partner: str):
        """
        Called when user selects a partner in the chat window.
        Checks for an existing session before requesting a new bundle.
        """
        if self.chat_view:
            history = self.crypt_services.db.get_messages(partner)
            self.chat_view.load_chat_history(history)

        # Always check user availability and fetch the latest bundle.
        # This ensures we have the bundle in memory even if a session was loaded from disk,
        # and also confirms if the user is online.
        # The server will provide a one-time-pre-key if needed for a new session,
        # or we can just use the bundle to re-validate an existing one.
        payload = {
            "status": "User_Select",
            "user_id": partner
        }
        self.network.send_payload(json.dumps(payload))
        if self.chat_view:
            # Give immediate feedback while we wait for the network response
            self.chat_view.set_status(f"Checking availability of {partner}...", "blue")
            self.chat_view.set_input_enabled(False)

    def request_bundle_for_partner(self, partner_sname: str):
        """Requests a key bundle for a specific partner."""
        bundle_request_payload = {
            "status": "request_key_bundle",
            "user_id": partner_sname
        }
        self.network.send_payload(json.dumps(bundle_request_payload))

    def process_pending_message(self, partner_name: str):
        """Processes a cached message after a bundle has been received."""
        encrypted_payload = self.pending_messages.pop(partner_name, None)
        if encrypted_payload:
            decryption_result = self.crypt_services.decrypt_message(partner_name, encrypted_payload)
            if decryption_result not in ("NEEDS_BUNDLE", None):
                self.crypt_services.db.add_message(partner_name, partner_name, decryption_result)
                if self.chat_view.current_partner == partner_name:
                    self.chat_view.add_message(partner_name, decryption_result)
            else:
                print(f"Error: Decryption failed for pending message from {partner_name}.")


    # Internal Logic
    def on_login_success(self):
        """
        Swaps the login window with the chat window and checks for pending friend requests.
        """
        # Save contacts before closing login view
        if self.crypt_services:
            self.crypt_services.save_contacts_to_disk()

        self.chat_view = ChatWindow(self.username)
        self.connect_chat_signals()
        self.load_contact_list() # Load contacts into the new chat view
        self.chat_view.show()
        self.login_view.close()

        # Check for pending friend requests
        self.check_pending_friend_requests()

    def check_pending_friend_requests(self):
        """
        Sends a request to the server to get pending friend requests.
        """
        payload = {
            "command": "get_pending_friend_requests"
        }
        self.network.send_payload(json.dumps(payload))


    def load_contact_list(self):
        """
        Loads the contact list of the current logged in user
        """
        if self.chat_view and self.crypt_services:
            contacts = self.crypt_services.load_contacts_from_disk()
            for contact in contacts:
                self.chat_view.contact_list.addItem(contact)
            print(f"Loaded {len(contacts)} contacts.")

    @Slot()
    def shutdown(self):
        """
        Gracefully shuts down the network service when the app is closing.
        """
        print("AppController: Initiating shutdown...")
        if self.network:
            self.network.shutdown()
