import wx
import threading
import socket

host = socket.gethostname()
addresses = socket.getaddrinfo(host, None, socket.AF_INET6)
IP = addresses[-1][4][0]
IP = "2409:40c1:10de:eb68:b17d:98cd:f871:3aff"
port = 12345


def enct(string):
    key = {'a': '@', 'b': '^', 'c': '&', 'd': '*', 'e': '/', 'f': '.', 'g': '{', 'h': '}', 'i': '+', 'j': '=', 'k': '#',
           'l': '!', 'm': '<', 'n': '_', 'o': '|', 'p': '~', 'q': '$', 'r': '%', 's': '`', 't': '(', 'u': ')', 'v': '-',
           'w': '2', 'x': '3', 'y': '6', 'z': '8', ' ': '0'}
    li = []
    for i in string:
        b = key[i]
        li.append(b)
    string = "".join(li)
    return string


def dect(string):
    key = {'@': 'a', '^': 'b', '&': 'c', '*': 'd', '/': 'e', '.': 'f', '{': 'g', '}': 'h', '+': 'i', '=': 'j', '#': 'k',
           '!': 'l', '<': 'm', '_': 'n', '|': 'o', '~': 'p', '$': 'q', '%': 'r', '`': 's', '(': 't', ')': 'u', '-': 'v',
           '2': 'w', '3': 'x', '6': 'y', '8': 'z', '0': ' '}
    li = []
    for i in string:
        b = key[i]
        li.append(b)
    string = "".join(li)
    return string


class LoginRegistrationFrame(wx.Frame):
    def __init__(self, parent, title):
        super().__init__(parent, title=title, size=(300, 150))

        self.panel = wx.Panel(self)

        self.sizer = wx.BoxSizer(wx.VERTICAL)

        self.login_button = wx.Button(self.panel, label="Login")
        self.login_button.Bind(wx.EVT_BUTTON, self.on_login_click)
        self.sizer.Add(self.login_button, 0, wx.ALL | wx.CENTER, 5)

        self.register_button = wx.Button(self.panel, label="Register")
        self.register_button.Bind(wx.EVT_BUTTON, self.on_register_click)
        self.sizer.Add(self.register_button, 0, wx.ALL | wx.CENTER, 5)

        self.panel.SetSizer(self.sizer)
        self.Show(True)

    def on_login_click(self, event):
        print("Login button clicked!")
        self.login_button.Destroy()
        self.register_button.Destroy()

        # Create a layout for the username field
        self.user_text = wx.StaticText(self.panel, label="Username - ", pos=(50, 25))
        self.sizer.Add(self.user_text, 0, wx.ALIGN_CENTER, 5)
        self.message = wx.TextCtrl(self.panel, pos=(115, 25))
        hsizer = wx.BoxSizer(wx.HORIZONTAL)
        hsizer.Add(self.message, 1, wx.EXPAND, 5)

        # Create a layout for the password field
        self.pass_text = wx.StaticText(self.panel, label="Password - ", pos=(50, 55))
        self.sizer.Add(self.pass_text, 0, wx.ALIGN_CENTER, 5)
        self.message2 = wx.TextCtrl(self.panel, style=wx.TE_PASSWORD, pos=(115, 55))
        hsizer.Add(self.message2, 1, wx.EXPAND | wx.ALL, 5)

        # Add a login button
        self.submit_button = wx.Button(self.panel, label="Login")
        self.submit_button.Bind(wx.EVT_BUTTON, self.submit_login)
        hsizer.Add(self.submit_button, 0, wx.ALL, 5)

        self.sizer.Add(hsizer, 1, wx.EXPAND | wx.ALL, 5)

        # Status message
        self.status_msg = wx.StaticText(self.panel, label="")
        self.sizer.Add(self.status_msg, 0, wx.ALIGN_CENTER, 5)

        self.panel.Layout()

    def submit_login(self, event):
        username = self.message.GetValue()
        passw = self.message2.GetValue()

        if not username or not passw:
            self.status_msg.SetLabel("Please enter both username and password")
            return

        # Send login command first
        self.clientDNS_socket.sendall(('login').encode())

        # Then send credentials
        req = username + '#' + passw
        self.clientDNS_socket.sendall(req.encode())

        # Receive response
        reqr = self.clientDNS_socket.recv(2048).decode()

        if reqr:
            if (reqr == '1'):
                reqr1 = 'sendport'
                self.clientDNS_socket.send(reqr1.encode())
                portno = self.clientDNS_socket.recv(2048).decode()
                port_num = int(portno)

                # Launch the messaging GUI
                self.panel.Destroy()
                frame1 = TextMessagingGUI(username=username)
                frame1.client(port_num)

            elif (reqr == 'Credfail'):
                self.status_msg.SetLabel("Username, Password don't match")
            else:
                self.status_msg.SetLabel("No Account Found!")
        else:
            self.status_msg.SetLabel("Server did not respond")

    def on_register_click(self, event):
        print("Register button clicked!")
        self.login_button.Destroy()
        self.register_button.Destroy()

        # Create a layout for the username field
        self.user_text = wx.StaticText(self.panel, label="New Username - ", pos=(50, 25))
        self.sizer.Add(self.user_text, 0, wx.ALIGN_CENTER, 5)
        self.message = wx.TextCtrl(self.panel, pos=(115, 25))
        hsizer = wx.BoxSizer(wx.HORIZONTAL)
        hsizer.Add(self.message, 1, wx.EXPAND, 5)

        # Create a layout for the password field
        self.pass_text = wx.StaticText(self.panel, label="New Password - ", pos=(50, 55))
        self.sizer.Add(self.pass_text, 0, wx.ALIGN_CENTER, 5)
        self.message2 = wx.TextCtrl(self.panel, style=wx.TE_PASSWORD, pos=(115, 55))
        hsizer.Add(self.message2, 1, wx.EXPAND | wx.ALL, 5)

        # Add a register button
        self.submit_button = wx.Button(self.panel, label="Register")
        self.submit_button.Bind(wx.EVT_BUTTON, self.submit_registration)
        hsizer.Add(self.submit_button, 0, wx.ALL, 5)

        self.sizer.Add(hsizer, 1, wx.EXPAND | wx.ALL, 5)

        # Status message
        self.status_msg = wx.StaticText(self.panel, label="")
        self.sizer.Add(self.status_msg, 0, wx.ALIGN_CENTER, 5)

        self.panel.Layout()

    def submit_registration(self, event):
        username = self.message.GetValue()
        passw = self.message2.GetValue()

        if not username or not passw:
            self.status_msg.SetLabel("Please enter both username and password")
            return

        # Send registration command first
        self.clientDNS_socket.sendall(('reg').encode())

        # Then send credentials
        req = username + '#' + passw
        self.clientDNS_socket.sendall(req.encode())

        # Receive response
        reqr = self.clientDNS_socket.recv(2048).decode()

        if reqr:
            if reqr == 'success':
                self.status_msg.SetLabel("Registration successful! You can now login.")
                # Add a button to return to login
                self.back_button = wx.Button(self.panel, label="Go to Login")
                self.back_button.Bind(wx.EVT_BUTTON, self.return_to_login)
                self.sizer.Add(self.back_button, 0, wx.ALL | wx.CENTER, 5)
                self.panel.Layout()
            elif reqr == 'AAE':
                self.status_msg.SetLabel("Username already exists. Try a different one.")
            else:
                self.status_msg.SetLabel("Registration failed. Please try again.")
        else:
            self.status_msg.SetLabel("Server did not respond")

    def return_to_login(self, event):
        # Recreate the login screen
        self.panel.DestroyChildren()
        self.sizer.Clear()

        self.login_button = wx.Button(self.panel, label="Login")
        self.login_button.Bind(wx.EVT_BUTTON, self.on_login_click)
        self.sizer.Add(self.login_button, 0, wx.ALL | wx.CENTER, 5)

        self.register_button = wx.Button(self.panel, label="Register")
        self.register_button.Bind(wx.EVT_BUTTON, self.on_register_click)
        self.sizer.Add(self.register_button, 0, wx.ALL | wx.CENTER, 5)

        self.panel.Layout()
        self.loginthread.join()
        self.start(

    def client(self):
        try:
            self.clientDNS_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
            self.clientDNS_socket.connect((IP, port, 0, 0))

        except ConnectionRefusedError:
            print("Tagret Refused to Connect")

        except (ConnectionError, ConnectionAbortedError):
            print("Connection closed by client.")

    def start(self):
        self.loginthread = threading.Thread(target=self.client)
        self.loginthread.start()


class TextMessagingGUI(wx.Frame):

    def __init__(self, parent=None, username="User"):
        super().__init__(parent, title=f"Text Messaging Client - {username}")

        self.username = username
        # For storing the partner's username
        self.partner_username = None

        central_panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        central_panel.SetSizer(sizer)

        # Add recipient input field
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

        # Chat history
        self.chat_history = wx.TextCtrl(central_panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.chat_history, 1, wx.EXPAND | wx.ALL, 5)

        # Message entry
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

        # Disable send until connected
        self.message_entry.Disable()
        self.send_button.Disable()


    def connect_to_recipient(self, event):
        self.partner_username = self.recipient_entry.GetValue()
        if not self.partner_username:
            wx.MessageBox("Please enter a username to chat with", "Error", wx.OK | wx.ICON_ERROR)
            return

        # Signal to server who we want to chat with
        self.client_socket.sendall(self.partner_username.encode())
        # Send our username to server
        self.client_socket.sendall(self.username.encode())

        # Enable message entry
        self.message_entry.Enable()
        self.send_button.Enable()
        self.connect_button.Disable()
        self.recipient_entry.Disable()

        self.status_bar.SetLabelText(f'Connected to {self.partner_username}')
        self.chat_history.AppendText(f"Connected to chat with {self.partner_username}\n")

    def send(self, event):
        try:
            if self.message_entry.GetValue():
                txt = self.message_entry.GetValue()
                encrypted_txt = enct(txt)
                self.client_socket.sendall(encrypted_txt.encode())
                self.chat_history.AppendText(f"\nMe: {txt}")
                self.message_entry.Clear()

        except (ConnectionError, ConnectionAbortedError):
            print("Connection closed by client.")
            self.status_bar.SetLabelText('Disconnected')

    def prompt(self):
        while True:
            try:
                received_data = self.client_socket.recv(2048).decode()
                if not received_data:
                    continue

                try:
                    # Try to decrypt, if it fails, it might be a system message
                    decrypted_data = dect(received_data)
                    print(f'Received String: {decrypted_data}')
                    self.chat_history.AppendText(f"\n{self.partner_username}: {decrypted_data}")
                    self.Refresh()
                except:
                    # Handle as system message
                    print(f'System message: {received_data}')
                    self.chat_history.AppendText(f"\nSystem: {received_data}")
                    self.Refresh()

            except (ConnectionError, ConnectionAbortedError):
                print("Connection closed by client.")
                wx.CallAfter(self.status_bar.SetLabelText, 'Disconnected')
                wx.CallAfter(self.connect_button.Enable)
                wx.CallAfter(self.recipient_entry.Enable)
                wx.CallAfter(self.message_entry.Disable)
                wx.CallAfter(self.send_button.Disable)
                break

    def client(self, port_num=None):
        # Use the port from login if available, otherwise use global port
        current_port = port_num if port_num is not None else port

        try:
            self.client_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
            self.client_socket.connect((IP, current_port, 0, 0))
            self.status_bar.SetLabelText('Connected to server')
            self.chat_history.AppendText("Connected to server. Enter a username to chat with.\n")

            # Start listening for messages
            t1 = threading.Thread(target=self.prompt)
            t1.daemon = True  # Daemon thread will terminate when main thread exits
            t1.start()

        except ConnectionRefusedError:
            print("Target Refused to Connect")
            self.status_bar.SetLabelText("Connection Error")
            wx.MessageBox("Could not connect to the server", "Connection Error", wx.OK | wx.ICON_ERROR)

        except (ConnectionError, ConnectionAbortedError):
            print("Connection closed by client.")
            self.status_bar.SetLabelText('Disconnected')


if __name__ == '__main__':
    app = wx.App(False)
    frame = LoginRegistrationFrame(None, "Login or Register")
    frame.start()
    app.MainLoop()
