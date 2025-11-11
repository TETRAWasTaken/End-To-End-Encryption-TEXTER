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

    @Slot()
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

        elif status == "Encrypted":
            if self.chat_view:
                sender = message.get("sender_user_id")
                # Ensure we only process messages not from ourselves
                if sender != self.username:
                    encrypted_payload = message.get("text")  # 'text' holds the crypto dict

                    # Decrypt
                    plaintext = self.crypt_services.decrypt_message(sender, encrypted_payload)
                    self.chat_view.add_message(sender, plaintext)

            else:
                print("Received chat message but no chat view is active.")

        elif status == "User_Select":
            if message == "User Available":
                if self.chat_view:
                    self.chat_view.set_status("User is available, fetching keys...", "blue")
                    partner = self.chat_view.current_partner
                    print(f"Requesting the key bundle of {partner}")
                    bundle_request_payload = {
                        "status": "request_key_bundle",
                        "user_id": partner
                    }
                    self.network.send_payload(json.dumps(bundle_request_payload))
            elif message == "User Not Online":
                if self.chat_view:
                    self.chat_view.set_status("User is offline. They will receive the message upon login.", "orange")
                    partner = self.chat_view.current_partner
                    print(f"Requesting the key bundle of {partner}")
                    bundle_request_payload = {
                        "status": "request_key_bundle",
                        "user_id": partner
                    }
                    self.network.send_payload(json.dumps(bundle_request_payload))
            elif message == "User Not Available":
                if self.chat_view:
                    self.chat_view.set_status("User not available", "red")
                    self.chat_view.set_input_enabled(False)

        elif status == "key_bundle_ok":
            partner_username = message.get("user_id")
            if partner_username and self.crypt_services and partner_username != self.username:
                self.crypt_services.store_partner_bundle(partner_username, message)
                print(f"Cached and deserialized bundle for {partner_username}")

                if self.chat_view and self.chat_view.current_partner == partner_username:
                    self.chat_view.set_status(f"Ready to chat with {partner_username}", "green")
                    self.chat_view.set_input_enabled(True)

        elif status == "key_bundle_fail":
            if self.chat_view:
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

    async def async_register(self, username: str, password: str):
        self.username = username
        self.crypt_services = CryptServices(username)

        try:
            self.public_bundle = await asyncio.to_thread(
                self.crypt_services.generate_and_save_key, password
            )
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
            self.network.send_raw("publish_keys")
            self.network.send_payload(json.dumps(self.public_bundle))
            self.public_bundle = None
        else:
            print("Error: Public key bundle not found.")

    @Slot(str, str)
    def handle_send_message(self, partner: str, text: str):
        if partner not in self.crypt_services.partner_bundles:
            self.chat_view.set_status(f"Cannot send message. No key bundle for {partner}. Please re-select them.", "red")
            return

        encrypted_payload = self.crypt_services.encrypt_message(partner, text)

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
        Called when user selects a partner in the chat window
        """
        payload = {
            "status": "User_Select",
            "user_id": partner
        }
        self.network.send_payload(json.dumps(payload))

    # Internal Logic
    def on_login_success(self):
        """
        Swaps the login window with the chat window
        """
        # Save contacts before closing login view
        if self.crypt_services:
            self.crypt_services.save_contacts_to_disk()

        self.chat_view = ChatWindow(self.username)
        self.connect_chat_signals()
        self.load_contact_list() # Load contacts into the new chat view
        self.chat_view.show()
        self.login_view.close()

    def load_contact_list(self):
        """
        Loads the contact list of the current logged in user
        """
        if self.chat_view and self.crypt_services:
            contacts = self.crypt_services.load_contacts_from_disk()
            for contact in contacts:
                self.chat_view.contact_list.addItem(contact)
            print(f"Loaded {len(contacts)} contacts.")
