from PySide6.QtCore import Slot, Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLineEdit, QPushButton,
                               QLabel, QHBoxLayout)

class LoginWindow(QWidget):
    """
    The login and registration window for the application.

    This class provides the user interface for entering a username and password,
    with options to either log in to an existing account or register a new one.
    It emits signals based on user actions, which are handled by the
    AppController.
    """
    login_requested = Signal(str, str)
    registration_requested = Signal(str, str)

    def __init__(self):
        """
        Initializes the LoginWindow, setting up the UI components and
        connecting signals to their respective slots.
        """
        super().__init__()
        self.setWindowTitle("TEXTER - Login")
        self.setObjectName("LoginWindow")
        self.setMinimumWidth(300)

        self.user_input = QLineEdit(placeholderText="Username")
        self.pass_input = QLineEdit(placeholderText="Password")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_btn = QPushButton("Login")
        self.register_btn = QPushButton("Register")

        self.status_label = QLabel("Connecting...")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.addWidget(self.user_input)
        layout.addWidget(self.pass_input)
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.login_btn)
        btn_layout.addWidget(self.register_btn)
        layout.addLayout(btn_layout)
        layout.addWidget(self.status_label)

        self.login_btn.clicked.connect(self.on_login_click)
        self.register_btn.clicked.connect(self.on_register_click)

        self.disable_buttons()
        self.set_status("Connecting...", "info")

    def on_login_click(self):
        """
        Handles the click event of the 'Login' button, emitting the
        `login_requested` signal with the entered credentials.
        """
        user = self.user_input.text()
        password = self.pass_input.text()
        if user and password:
            self.login_requested.emit(user, password)
            self.set_status("Logging in...", "info")

    def on_register_click(self):
        """
        Handles the click event of the 'Register' button, emitting the
        `registration_requested` signal with the entered credentials.
        """
        user = self.user_input.text()
        password = self.pass_input.text()
        if user and password:
            self.registration_requested.emit(user, password)
            self.set_status("Registering...", "info")

    @Slot()
    def enable_buttons(self):
        """
        Enables the login and register buttons, typically after a successful
        connection to the server.
        """
        self.login_btn.setEnabled(True)
        self.register_btn.setEnabled(True)
        self.set_status("Connected. Ready", "success")

    @Slot()
    def disable_buttons(self):
        """
        Disables the login and register buttons, typically while connecting or
        during an operation.
        """
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)

    @Slot(str, str)
    def set_status(self, text: str, status_type: str = "error"):
        """
        Sets the status text and style for user feedback.

        Args:
            text: The message to display.
            status_type: The type of status ('error', 'info', 'success'),
                         used for styling.
        """
        self.status_label.setText(text)
        self.status_label.setProperty("status", status_type)
        self.style().unpolish(self.status_label)
        self.style().polish(self.status_label)