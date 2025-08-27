import asyncio
import json
import socket
import ssl
import sys
import threading
import x3dh
import websockets
import wx

host = socket.gethostname()
IP = "localhost"

class LoginRegistrationFrame(wx.Frame):
    """
    The initial GUI frame for the application.
    This class handles the user interface for both logging in and registering a new account.
    It manages the connection to the server and transitions to the main chat GUI upon successful login.
    """
    def __init__(self, parent, title):
        """
        Initializes the LoginRegistrationFrame.
        Args:
            parent: The parent window.
            title (str): The title for the window frame.
        """
        super().__init__(parent, title=title, size=(300, 200))

        self.panel = wx.Panel(self)
        self.sizer = wx.BoxSizer(wx.VERTICAL)

        self.status_label = wx.StaticText(self.panel, label="Connecting to server...")
        self.sizer.Add(self.status_label, 0, wx.ALL | wx.CENTER, 5)

        self.login_button = wx.Button(self.panel, label="Login")
        self.login_button.Bind(wx.EVT_BUTTON, self.on_login_click)
        self.sizer.Add(self.login_button, 0, wx.ALL | wx.CENTER, 5)

        self.register_button = wx.Button(self.panel, label="Register")
        self.register_button.Bind(wx.EVT_BUTTON, self.on_register_click)
        self.sizer.Add(self.register_button, 0, wx.ALL | wx.CENTER, 5)

        self.login_button.Disable()
        self.register_button.Disable()

        self.panel.SetSizer(self.sizer)
        self.Show(True)

        self.loop = None
        self.clientDNS_socket = None
        self.login_thread = None

    def on_login_click(self, event):
        """
        Event handler for the 'Login' button click.
        It dynamically changes the UI to display username and password entry fields for logging in.
        Args:
            event: The wx event object.
        """
        self.login_button.Destroy()
        self.register_button.Destroy()
        self.status_label.Destroy()

        self.user_text = wx.StaticText(self.panel, label="Username - ")
        self.message = wx.TextCtrl(self.panel)
        hsizer = wx.BoxSizer(wx.HORIZONTAL)
        hsizer.Add(self.user_text, 0, wx.ALIGN_CENTER_VERTICAL | wx.ALL, 5)
        hsizer.Add(self.message, 1, wx.EXPAND | wx.ALL, 5)
        self.sizer.Add(hsizer)

        self.pass_text = wx.StaticText(self.panel, label="Password - ")
        self.message2 = wx.TextCtrl(self.panel, style=wx.TE_PASSWORD)
        hsizer2 = wx.BoxSizer(wx.HORIZONTAL)
        hsizer2.Add(self.pass_text, 0, wx.ALIGN_CENTER_VERTICAL | wx.ALL, 5)
        hsizer2.Add(self.message2, 1, wx.EXPAND | wx.ALL, 5)
        self.sizer.Add(hsizer2)

        self.submit_button = wx.Button(self.panel, label="Login")
        self.submit_button.Bind(wx.EVT_BUTTON, self.submit_login)
        self.sizer.Add(self.submit_button, 0, wx.ALL | wx.CENTER, 5)

        self.status_msg = wx.StaticText(self.panel, label="")
        self.sizer.Add(self.status_msg, 0, wx.ALL | wx.CENTER, 5)

        self.panel.Layout()

    def submit_login(self, event):
        """
        Event handler for the 'Submit' button on the login form.
        Retrieves credentials from input fields and initiates the asynchronous login process.
        Args:
            event: The wx event object.
        """
        username = self.message.GetValue()
        passw = self.message2.GetValue()

        if not username or not passw:
            self.status_msg.SetLabel("Please enter both username and password")
            return
        
        asyncio.run_coroutine_threadsafe(self.do_login(username, passw), self.loop)

    def reset_login(self):
        """Resets the login form fields."""
        self.on_login_click(None)

    async def do_login(self, username, passw):
        """
        Asynchronously handles the login communication with the server.
        Sends login credentials and processes the server's response.
        Args:
            username (str): The username to log in with.
            passw (str): The password for the user.
        """
        if not self.clientDNS_socket:
            wx.CallAfter(self.status_msg.SetLabel, "Not connected to server.")
            return
        try:
            await self.clientDNS_socket.send('login')
            req = json.dumps({'username': username, 'password': passw})
            await self.clientDNS_socket.send(req)
            response = await self.clientDNS_socket.recv()

            if response == '1':
                wx.CallAfter(self.on_login_success, username)
            elif response == 'Credfail':
                wx.CallAfter(self.status_msg.SetLabel, "Username, Password don't match")
                self.reset_login()
            else:
                wx.CallAfter(self.status_msg.SetLabel, "No Account Found!")
        except Exception as e:
            print(f"Login failed: {e}")
            wx.CallAfter(self.status_msg.SetLabel, "An error occurred during login.")

    def on_login_success(self, username):
        """
        Handles the successful login event.
        Destroys the current login panel and initializes the main TextMessagingGUI.
        Args:
            username (str): The username of the logged-in user.
        """
        self.panel.Destroy()
        TextMessagingGUI(username=username, loop=self.loop, server_socket=self.clientDNS_socket)
        self.Show(False)

    def on_register_click(self, event):
        """
        Event handler for the 'Register' button click.
        It dynamically changes the UI to display username and password entry fields for registration.
        Args:
            event: The wx event object.
        """
        self.login_button.Destroy()
        self.register_button.Destroy()
        self.status_label.Destroy()

        self.user_text = wx.StaticText(self.panel, label="New Username - ")
        self.message = wx.TextCtrl(self.panel)
        hsizer = wx.BoxSizer(wx.HORIZONTAL)
        hsizer.Add(self.user_text, 0, wx.ALIGN_CENTER_VERTICAL | wx.ALL, 5)
        hsizer.Add(self.message, 1, wx.EXPAND | wx.ALL, 5)
        self.sizer.Add(hsizer)

        self.pass_text = wx.StaticText(self.panel, label="New Password - ")
        self.message2 = wx.TextCtrl(self.panel, style=wx.TE_PASSWORD)
        hsizer2 = wx.BoxSizer(wx.HORIZONTAL)
        hsizer2.Add(self.pass_text, 0, wx.ALIGN_CENTER_VERTICAL | wx.ALL, 5)
        hsizer2.Add(self.message2, 1, wx.EXPAND | wx.ALL, 5)
        self.sizer.Add(hsizer2)

        self.submit_button = wx.Button(self.panel, label="Register")
        self.submit_button.Bind(wx.EVT_BUTTON, self.submit_registration)
        self.sizer.Add(self.submit_button, 0, wx.ALL | wx.CENTER, 5)

        self.status_msg = wx.StaticText(self.panel, label="")
        self.sizer.Add(self.status_msg, 0, wx.ALL | wx.CENTER, 5)
        
        self.panel.Layout()

    def submit_registration(self, event):
        """
        Event handler for the 'Submit' button on the registration form.
        Retrieves new user credentials and initiates the asynchronous registration process.
        Args:
            event: The wx event object.
        """
        username = self.message.GetValue()
        passw = self.message2.GetValue()

        if not username or not passw:
            self.status_msg.SetLabel("Please enter both username and password")
            return
            
        asyncio.run_coroutine_threadsafe(self.do_registration(username, passw), self.loop)

    async def do_registration(self, username, passw):
        """
        Asynchronously handles the registration communication with the server.
        Sends new account details and processes the server's response.
        Args:
            username (str): The new username to register.
            passw (str): The password for the new account.
        """
        if not self.clientDNS_socket:
            wx.CallAfter(self.status_msg.SetLabel, "Not connected to server.")
            return
        try:
            await self.clientDNS_socket.send('reg')
            req = json.dumps({'username': username, 'password': passw})
            await self.clientDNS_socket.send(req)
            response = await self.clientDNS_socket.recv()

            if response == 'success':
                try:
                    alice = x3dh.X3DH(username)
                    key_bundle = alice.generate_key_bundle()

                    await self.clientDNS_socket.send('publish_keys')
                    await self.clientDNS_socket.send(json.dumps(key_bundle))

                    bundle_response = await self.clientDNS_socket.recv()
                    if bundle_response == 'keys_ok':
                        wx.CallAfter(self.on_registration_success)
                    else:
                        wx.CallAfter(self.status_msg.SetLabel, "Registration OK, Key publishing failed")

                except Exception as e:
                    print(f"Registration failed: {e}")
                    wx.CallAfter(self.status_msg.SetLabel, "An error occurred during registration.")

            elif response == 'AAE':
                wx.CallAfter(self.status_msg.SetLabel, "Username already exists.")
            else:
                wx.CallAfter(self.status_msg.SetLabel, "Registration failed.")
        except Exception as e:
            print(f"Registration failed: {e}")
            wx.CallAfter(self.status_msg.SetLabel, "An error occurred during registration.")

    def on_registration_success(self):
        """
        Handles the successful registration event.
        Updates the UI to inform the user and provides an option to go back to the login screen.
        """
        self.status_msg.SetLabel("Registration successful! You can now login.")
        self.back_button = wx.Button(self.panel, label="Go to Login")
        self.back_button.Bind(wx.EVT_BUTTON, self.return_to_login)
        self.sizer.Add(self.back_button, 0, wx.ALL | wx.CENTER, 5)
        self.submit_button.Destroy()
        self.panel.Layout()

    def return_to_login(self, event):
        """
        Event handler to return to the initial login/register selection screen.
        Clears the current UI elements and reconstructs the initial buttons.
        Args:
            event: The wx event object.
        """
        self.panel.DestroyChildren()
        self.sizer.Clear()

        self.login_button = wx.Button(self.panel, label="Login")
        self.login_button.Bind(wx.EVT_BUTTON, self.on_login_click)
        self.sizer.Add(self.login_button, 0, wx.ALL | wx.CENTER, 5)

        self.register_button = wx.Button(self.panel, label="Register")
        self.register_button.Bind(wx.EVT_BUTTON, self.on_register_click)
        self.sizer.Add(self.register_button, 0, wx.ALL | wx.CENTER, 5)

        self.panel.Layout()

    async def client(self):
        """
        Asynchronously connects to the WebSocket server using SSL.
        It updates the UI based on the connection status and keeps the connection alive.
        """
        uri = f"wss://{IP}:12345"
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations(cafile='server.crt')
        try:
            self.clientDNS_socket = await websockets.connect(uri, ssl=ssl_context)
            wx.CallAfter(self.status_label.SetLabel, "Connected. Please login or register.")
            wx.CallAfter(self.login_button.Enable)
            wx.CallAfter(self.register_button.Enable)
            await self.clientDNS_socket.wait_closed()
        except Exception as e:
            print(f"Failed to connect or connection lost: {e}")
            wx.CallAfter(self.status_label.SetLabel, f"Connection failed: {e}")

    def run_async_loop(self):
        """
        Sets up and runs the asyncio event loop for handling network operations.
        This method is intended to be run in a separate thread.
        """
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.client())

    def start(self):
        """
        Starts the client's network communication in a separate thread to prevent blocking the GUI.
        """
        self.login_thread = threading.Thread(target=self.run_async_loop)
        self.login_thread.daemon = True
        self.login_thread.start()


class TextMessagingGUI(wx.Frame):
    """
    The main text messaging interface for the client.
    This class provides the UI for chatting with other users, sending and receiving messages,
    and managing the connection state.
    """

    def __init__(self, parent=None, username="User", loop=None, server_socket=None):
        """
        Initializes the TextMessagingGUI.
        Args:
            parent: The parent window.
            username (str): The username of the current user.
            loop: The asyncio event loop for network operations.
            server_socket: The active WebSocket connection to the server.
        """
        super().__init__(parent, title=f"Text Messaging Client - {username}")
        self.session_keys = {}

        self.username = username
        self.partner_username = None
        self.loop = loop
        self.client_socket = server_socket

        central_panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        central_panel.SetSizer(sizer)

        recipient_panel = wx.Panel(central_panel)
        recipient_sizer = wx.BoxSizer(wx.HORIZONTAL)
        recipient_panel.SetSizer(recipient_sizer)

        recipient_label = wx.StaticText(recipient_panel, label="Chat with: ")
        self.recipient_entry = wx.TextCtrl(recipient_panel)
        self.connect_button = wx.Button(recipient_panel, label="Connect")
        self.connect_button.Bind(wx.EVT_BUTTON, self.connect_to_recipient)

        recipient_sizer.Add(recipient_label, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        recipient_sizer.Add(self.recipient_entry, 1, wx.EXPAND | wx.ALL, 5)
        recipient_sizer.Add(self.connect_button, 0, wx.ALL, 5)

        sizer.Add(recipient_panel, 0, wx.EXPAND | wx.ALL, 5)

        self.chat_history = wx.TextCtrl(central_panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.chat_history, 1, wx.EXPAND | wx.ALL, 5)

        self.message_entry = wx.TextCtrl(central_panel, style=wx.TE_PROCESS_ENTER)
        self.message_entry.Bind(wx.EVT_TEXT_ENTER, self.send)
        self.send_button = wx.Button(central_panel, label="Send")
        self.send_button.Bind(wx.EVT_BUTTON, self.send)

        hsizer = wx.BoxSizer(wx.HORIZONTAL)
        hsizer.Add(self.message_entry, 1, wx.EXPAND, 5)
        hsizer.Add(self.send_button, 0, wx.HORIZONTAL, 5)
        sizer.Add(hsizer, 0, wx.EXPAND | wx.ALL, 5)

        self.status_bar = wx.StaticText(central_panel, label="Disconnected")
        sizer.Add(self.status_bar, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.Show(True)

        self.message_entry.Disable()
        self.send_button.Disable()
        
        self.client()

    def connect_to_recipient(self, event):
        """
        Event handler for the 'Connect' button.
        Gets the recipient's username and initiates the connection process.
        Args:
            event: The wx event object.
        """
        self.partner_username = self.recipient_entry.GetValue()
        if not self.partner_username:
            wx.MessageBox("Please enter a username to chat with", "Error", wx.OK | wx.ICON_ERROR)
            return

        asyncio.run_coroutine_threadsafe(self.do_connect(), self.loop)

    async def do_connect(self):
        """
        Asynchronously sends the local and partner usernames to the server to establish a chat session.
        Updates the UI to enable chatting upon successful connection.
        """
        try:
            await self.client_socket.send('get_keys')
            await self.client_socket.send(self.partner_username)
            await self.client_socket.send(self.username)

            wx.CallAfter(self.message_entry.Enable)
            wx.CallAfter(self.send_button.Enable)
            wx.CallAfter(self.connect_button.Disable)
            wx.CallAfter(self.recipient_entry.Disable)
            wx.CallAfter(self.status_bar.SetLabelText, f'Connected to {self.partner_username}')
            wx.CallAfter(self.chat_history.AppendText, f"Connected to chat with {self.partner_username}\n")

        except Exception as e:
            print(f"Error connecting to recipient: {e}")
            wx.CallAfter(self.status_bar.SetLabelText, "Connection Error")

    def send(self, event):
        """
        Event handler for sending a message (via button click or Enter key).
        Retrieves text from the input field and calls the async send method.
        Args:
            event: The wx event object.
        """
        txt = self.message_entry.GetValue()
        if txt:
            asyncio.run_coroutine_threadsafe(self.do_send(txt), self.loop)
            self.message_entry.Clear()

    async def do_send(self, txt):
        """
        Asynchronously sends an encrypted message to the server.
        Args:
            txt (str): The plain text message to be encrypted and sent.
        """
        try:
            encrypted_txt = enct(txt)
            await self.client_socket.send(encrypted_txt)
            wx.CallAfter(self.chat_history.AppendText, f"\nMe: {txt}")
        except Exception as e:
            print(f"Error sending message: {e}")
            wx.CallAfter(self.status_bar.SetLabelText, 'Disconnected')


    async def prompt(self):
        """
        The main asynchronous loop for receiving messages from the server.
        Listens on the socket, decrypts incoming data, and updates the chat history.
        """
        while self.client_socket:
            try:
                received_data = await self.client_socket.recv()
                
                try:
                    decrypted_data = dect(received_data)
                    wx.CallAfter(self.chat_history.AppendText, f"\n{self.partner_username}: {decrypted_data}")
                except Exception:
                    wx.CallAfter(self.chat_history.AppendText, f"\nSystem: {received_data}")

            except websockets.exceptions.ConnectionClosed:
                print("Connection closed.")
                wx.CallAfter(self.status_bar.SetLabelText, 'Disconnected')
                break
            except Exception as e:
                print(f"Error in prompt: {e}")
                wx.CallAfter(self.status_bar.SetLabelText, 'Disconnected')
                break

    def client(self):
        """
        Initializes the client's state upon GUI creation.
        Updates the UI to show connection status and starts the message receiving loop.
        """
        if self.client_socket:
            self.status_bar.SetLabelText('Connected to server')
            self.chat_history.AppendText("Connected to server. Enter a username to chat with.\n")
            asyncio.run_coroutine_threadsafe(self.prompt(), self.loop)
        else:
            self.status_bar.SetLabelText("Connection Error")
            wx.MessageBox("Could not connect to the server", "Connection Error", wx.OK | wx.ICON_ERROR)


if __name__ == '__main__':
    """
    Main entry point for the application.
    Initializes the wx.App, creates the LoginRegistrationFrame, starts the networking
    thread, and enters the wxPython main event loop.
    """
    try:
        app = wx.App(False)
        frame = LoginRegistrationFrame(None, "Login or Register")
        frame.start()
        app.MainLoop()
    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)