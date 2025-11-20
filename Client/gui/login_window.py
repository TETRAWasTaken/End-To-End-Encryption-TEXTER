from PySide6.QtCore import Slot, Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLineEdit, QPushButton,
                               QLabel, QHBoxLayout)

class LoginWindow(QWidget):
    """
    The GUI code of the Login window of the application
    """
    login_requested = Signal(str, str)
    registration_requested = Signal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("TEXTER - Login")
        self.setMinimumWidth(300)

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Username")

        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Password")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_btn = QPushButton("Login")
        self.register_btn = QPushButton("Register")

        self.status_label = QLabel("Connecting...")
        self.status_label.setStyleSheet("color: gray")
        self.status_label.setWordWrap(True)

        # Layout
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

    def on_login_click(self):
        user = self.user_input.text()
        password = self.pass_input.text()

        if user and password:
            self.login_requested.emit(user, password)
            self.status_label.setText("Logging in...")

    def on_register_click(self):
        user = self.user_input.text()
        password = self.pass_input.text()

        if user and password:
            self.registration_requested.emit(user, password)
            self.status_label.setText("Registering...")

    @Slot()
    def enable_buttons(self):
        self.login_btn.setEnabled(True)
        self.register_btn.setEnabled(True)
        self.set_status("Connected. Ready", "green")

    @Slot()
    def disable_buttons(self):
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)

    @Slot()
    def set_status(self, text: str, color: str = "red"):
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color}")