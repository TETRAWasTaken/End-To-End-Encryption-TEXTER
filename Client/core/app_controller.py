import json

from PySide6.QtCore import QObject, Slot, Signal
import asyncio
from Client.gui.login_window import LoginWindow
from Client.gui.chat_window import ChatWindow
from Client.services.network_service import NetworkService
from Client.services.crypt_services import CryptServices

class AppController(QObject):
    """
    The main controller for the client application.

    This class orchestrates the interactions between the GUI (LoginWindow,
    ChatWindow), the network service, and the cryptography service. It manages
    the application's state, handles user input, and processes messages
    received from the server.
    """
    def __init__(self):
        """
        Initializes the AppController, setting up the initial state, services,
        and GUI components.
        """
        super().__init__()

        self.username = None
        self.current_state = "Login"
        self.public_bundle = None
        self.pending_messages = {}

        self.network = NetworkService()
        self.login_view = LoginWindow()
        self.chat_view = None
        self.crypt_services = None

        self.connect_network_signals()
        self.connect_login_signals()

    def run(self):
        """
        Starts the application by showing the login window and initiating the
        network connection.
        """
        self.login_view.show()
        self.network.start()
        self.network.connect()

    def connect_network_signals(self):
        """
        Connects signals from the NetworkService to the appropriate slots in
        this controller.
        """
        self.network.connected.connect(self.on_network_connected)
        self.network.disconnected.connect(self.on_network_disconnected)
        self.network.message_received.connect(self.handle_network_message)
        self.network.error_occured.connect(self.on_network_error)
        self.network.reconnecting.connect(self.on_network_reconnecting)

    def connect_login_signals(self):
        """
        Connects signals from the LoginWindow to the appropriate slots in this
        controller.
        """
        self.login_view.login_requested.connect(self.handle_login_request)
        self.login_view.registration_requested.connect(self.handle_register_request)

    def connect_chat_signals(self):
        """
        Connects signals from the ChatWindow to the appropriate slots in this
        controller.
        """
        if self.chat_view:
            self.chat_view.send_message_requested.connect(self.handle_send_message)
            self.chat_view.partner_selected.connect(self.handle_partner_select)
            self.chat_view.friend_request_sent.connect(self.handle_friend_request)
            self.chat_view.friend_request_accepted.connect(self.handle_friend_request_accepted)

    @Slot()
    def on_network_reconnecting(self):
        """
        Slot that handles the reconnection attempt to the server.
        """
        view = self.chat_view if self.chat_view and self.chat_view.isVisible() else self.login_view

        if hasattr(view, 'set_status'):
            view.set_status("Connection Lost. Reconnecting...", "orange")
        if hasattr(view, 'disable_buttons'):
            view.disable_buttons()

    @Slot()
    def on_network_connected(self):
        """
        Slot that handles the successful connection to the server by enabling
        the login view buttons.
        """
        self.login_view.enable_buttons()

    @Slot()
    def on_network_disconnected(self):
        """
        Slot that handles disconnection from the server, updating the UI to
        reflect the disconnected state.
        """
        view = self.chat_view if self.chat_view and self.chat_view.isVisible() else self.login_view
        if hasattr(view, 'set_status'):
            view.set_status("Disconnected", "red")
        if hasattr(view, 'disable_buttons'):
            view.disable_buttons()

    @Slot(str)
    def on_network_error(self, err_message: str):
        """
        Slot that handles network errors, displaying an error message in the
        current view.

        Args:
            err_message: The error message received from the network service.
        """
        view = self.chat_view if self.chat_view and self.chat_view.isVisible() else self.login_view
        if hasattr(view, 'set_status'):
            view.set_status(f"Error : {err_message}", "red")

    @Slot(dict)
    def handle_network_message(self, payload: dict):
        """
        Central handler for all messages received from the server.

        This method parses the message payload and routes it to the appropriate
        handler based on its status and content.

        Args:
            payload: The dictionary containing the message data from the server.
        """
        status = payload.get("status")
        message = payload.get("message")

        view = self.login_view if self.current_state in ("login", "register", "register_keys") else self.chat_view

        if status == "ok":
            if message == "success" or (isinstance(message, dict) and message.get("text") == "success"):

                if isinstance(message, dict) and "session_token" in message:
                    token = message["session_token"]
                    self.network.set_session_token(token)

                self.current_state = "chat"
                self.on_login_success()
                return

            elif message == "Registration Successful":
                view.set_status("Registered! Publishing keys...", "blue")
                self.current_state = "register_keys"
                self.network.schedule_task(self.handle_publish_keys())

            elif message == "keys_ok":
                view.set_status("Keys published! You can log in.", "green")
                self.current_state = "login"

        elif status == "error":
            view.set_status(f"Error: {message}", "red")

        elif status == "new_friend_request" and self.chat_view:
            self.chat_view.add_friend_request_notification(message.get("from"))

        elif status == "friend_request_status" and self.chat_view:
            self.chat_view.show_friend_request_status(message)

        elif status == "friend_request_accepted" and self.chat_view:
            new_friend = message.get("friend_username")
            if new_friend:
                self.chat_view.add_contact(new_friend)
                self.crypt_services.save_contacts_to_disk()
                self.request_bundle_for_partner(new_friend)

        elif status == "pending_friend_requests" and self.chat_view:
            for from_user in message:
                self.chat_view.add_friend_request_notification(from_user)

        elif status == "Encrypted" and self.chat_view:
            self.handle_encrypted_message(message)

        elif status == "User_Select" and self.chat_view:
            self.handle_user_select_response(message)

        elif status == "key_bundle_ok" and self.chat_view:
            self.handle_key_bundle_response(message)

        elif status == "key_bundle_fail" and self.chat_view:
            self.handle_key_bundle_failure(message)

    def handle_encrypted_message(self, message: dict):
        """
        Handles an incoming encrypted message.

        Args:
            message: The message dictionary containing sender and payload.
        """
        sender = message.get("sender_user_id")
        if sender != self.username:
            encrypted_payload = message.get("text")
            decryption_result = self.crypt_services.decrypt_message(sender, encrypted_payload)
            if decryption_result == "NEEDS_BUNDLE":
                self.pending_messages[sender] = encrypted_payload
                self.request_bundle_for_partner(sender)
            elif decryption_result is not None:
                self.crypt_services.db.add_message(sender, sender, decryption_result)
                if self.chat_view.current_partner == sender:
                    self.chat_view.add_message(sender, decryption_result)

    def handle_user_select_response(self, message: str):
        """
        Handles the response from a 'User_Select' request.

        Args:
            message: The status message from the server.
        """
        if message in ("User Available", "User Available And Friends"):
            self.chat_view.set_status("User is available, fetching keys...", "blue")
            self.request_bundle_for_partner(self.chat_view.current_partner)
        elif message in ("User Not Online", "User Not Online but Friends"):
            self.chat_view.set_status("User is offline. They will receive the message upon login.", "orange")
            self.request_bundle_for_partner(self.chat_view.current_partner)
        elif message == "User Not Available":
            self.chat_view.set_status("User not available", "red")
            self.chat_view.set_input_enabled(False)
        elif message == "User Not Friend":
            self.chat_view.set_status("You can only chat with friends.", "red")
            self.chat_view.set_input_enabled(False)

    def handle_key_bundle_response(self, message: dict):
        """
        Handles a successful key bundle response from the server.

        Args:
            message: The dictionary containing the key bundle.
        """
        partner_username = message.get("user_id")
        if partner_username and self.crypt_services and partner_username != self.username:
            self.crypt_services.store_partner_bundle(partner_username, message)
            if self.chat_view.current_partner == partner_username:
                self.chat_view.set_status(f"Ready to chat with {partner_username}", "green")
                self.chat_view.set_input_enabled(True)
                if partner_username in self.pending_messages:
                    self.network.loop.call_soon_threadsafe(self.process_pending_message, partner_username)

    def handle_key_bundle_failure(self, message: str):
        """
        Handles a failed key bundle request.

        Args:
            message: The reason for the failure.
        """
        if message == "not_friends":
            self.chat_view.set_status("Cannot start a secure session. You are not friends with this user.", "red")
        else:
            self.chat_view.set_status("Selected partner cannot be contacted", "red")
        self.chat_view.set_input_enabled(False)

    @Slot(str, str)
    def handle_login_request(self, username: str, password: str):
        """
        Handles a login request from the LoginWindow.

        Args:
            username: The username entered by the user.
            password: The password entered by the user.
        """
        self.username = username
        self.login_view.set_status("Loading keys...", "blue")
        self.crypt_services = CryptServices(username)

        if not self.crypt_services.load_keys_from_disk(password):
            self.login_view.set_status("Invalid credentials", "red")
            self.current_state = "login"
            return

        self.network.set_credentials(username, password)

        self.login_view.set_status("Logging in...", "blue")
        self.current_state = "login"
        login_payload = {"command": "login", "credentials": {"username": username, "password": password}}
        self.network.send_payload(json.dumps(login_payload))

    @Slot(str, str)
    def handle_register_request(self, username: str, password: str):
        """
        Handles a registration request from the LoginWindow.

        Args:
            username: The username entered by the user.
            password: The password entered by the user.
        """
        self.login_view.set_status("Generating Keys...", "blue")
        self.network.schedule_task(self.async_register(username, password))

    @Slot(str)
    def handle_friend_request(self, friend_username: str):
        """
        Handles a friend request from the ChatWindow.

        Args:
            friend_username: The username of the user to send a friend request to.
        """
        payload = {"command": "friend_request", "from_user": self.username, "to_user": friend_username}
        self.network.send_payload(json.dumps(payload))

    @Slot(str)
    def handle_friend_request_accepted(self, from_user: str):
        """
        Handles the acceptance of a friend request from the ChatWindow.

        Args:
            from_user: The username of the user whose friend request is accepted.
        """
        payload = {"command": "accept_friend_request", "from_user": from_user, "to_user": self.username}
        self.network.send_payload(json.dumps(payload))

    async def async_register(self, username: str, password: str):
        """
        Asynchronously handles the registration process, including key generation.

        Args:
            username: The username for the new account.
            password: The password for the new account.
        """
        self.username = username
        self.crypt_services = CryptServices(username)
        try:
            self.public_bundle = await asyncio.to_thread(self.crypt_services.generate_and_save_key, password)
            if self.public_bundle is None:
                self.login_view.set_status("Username already exists on this device.", "red")
                return
            self.login_view.set_status("Registering...", "blue")
            self.current_state = "register"
            register_payload = {"command": "register", "credentials": {"username": username, "password": password}}
            self.network.send_payload(json.dumps(register_payload))
        except Exception as e:
            self.login_view.set_status(f"Error in register_request: {str(e)}", "red")

    async def handle_publish_keys(self):
        """
        Publishes the user's public key bundle to the server after successful
        registration.
        """
        if self.public_bundle:
            payload = {"command": "publish_keys", "bundle": self.public_bundle}
            self.network.send_payload(json.dumps(payload))
            self.public_bundle = None
        else:
            print("Error: Public key bundle not found.")

    @Slot(str, str)
    def handle_send_message(self, partner: str, text: str):
        """
        Handles the request to send a message from the ChatWindow.

        Args:
            partner: The username of the recipient.
            text: The plaintext message to send.
        """
        if partner not in self.crypt_services.partner_bundles:
            self.chat_view.set_status(f"Cannot send message. No key bundle for {partner}. Please re-select them.", "red")
            return
        encrypted_payload = self.crypt_services.encrypt_message(partner, text)
        self.crypt_services.db.add_message(partner, self.username, text)
        server_payload = {
            "status": "Encrypted",
            "message": {"text": encrypted_payload, "sender_user_id": self.username, "recv_user_id": partner}
        }
        self.network.send_payload(json.dumps(server_payload))

    @Slot(str)
    def handle_partner_select(self, partner: str):
        """
        Handles the selection of a chat partner in the ChatWindow.

        Args:
            partner: The username of the selected partner.
        """
        if self.chat_view:
            history = self.crypt_services.db.get_messages(partner)
            self.chat_view.load_chat_history(history)
        payload = {"status": "User_Select", "user_id": partner}
        self.network.send_payload(json.dumps(payload))
        if self.chat_view:
            self.chat_view.set_status(f"Checking availability of {partner}...", "blue")
            self.chat_view.set_input_enabled(False)

    def request_bundle_for_partner(self, partner_sname: str):
        """
        Requests a key bundle for a specific partner from the server.

        Args:
            partner_sname: The username of the partner.
        """
        bundle_request_payload = {"status": "request_key_bundle", "user_id": partner_sname}
        self.network.send_payload(json.dumps(bundle_request_payload))

    def process_pending_message(self, partner_name: str):
        """
        Processes a cached message after a key bundle has been received.

        Args:
            partner_name: The username of the partner whose message is pending.
        """
        encrypted_payload = self.pending_messages.pop(partner_name, None)
        if encrypted_payload:
            decryption_result = self.crypt_services.decrypt_message(partner_name, encrypted_payload)
            if decryption_result not in ("NEEDS_BUNDLE", None):
                self.crypt_services.db.add_message(partner_name, partner_name, decryption_result)
                if self.chat_view.current_partner == partner_name:
                    self.chat_view.add_message(partner_name, decryption_result)
            else:
                print(f"Error: Decryption failed for pending message from {partner_name}.")

    def on_login_success(self):
        """
        Handles the successful login by switching to the chat view and
        performing post-login tasks.
        """
        if self.chat_view and self.chat_view.isVisible():
            self.chat_view.set_status(f"Connected as {self.username}", "green")
            self.chat_view.set_input_enabled(True)
            return

        if self.crypt_services:
            self.crypt_services.save_contacts_to_disk()

        self.chat_view = ChatWindow(self.username)
        self.connect_chat_signals()
        self.load_contact_list()
        self.chat_view.show()
        self.login_view.close()
        self.check_pending_friend_requests()

    def check_pending_friend_requests(self):
        """
        Sends a request to the server to get any pending friend requests for the
        current user.
        """
        payload = {"command": "get_pending_friend_requests"}
        self.network.send_payload(json.dumps(payload))

    def load_contact_list(self):
        """
        Loads the user's contact list from the local database and populates
        the chat view.
        """
        if self.chat_view and self.crypt_services:
            contacts = self.crypt_services.load_contacts_from_disk()
            for contact in contacts:
                self.chat_view.contact_list.addItem(contact)
            print(f"Loaded {len(contacts)} contacts.")

    @Slot()
    def shutdown(self):
        """
        Gracefully shuts down the network service when the application is
        closing.
        """
        print("AppController: Initiating shutdown...")
        if self.network:
            self.network.shutdown()