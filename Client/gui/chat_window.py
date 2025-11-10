from PySide6.QtWidgets import (QMainWindow, QVBoxLayout, QWidget,
                               QTextEdit, QLineEdit, QPushButton,
                               QSplitter, QListWidget, QLabel, QHBoxLayout)
from PySide6.QtCore import Slot, Signal, Qt
from Client.core.app_controller import AppController

class ChatWindow(QMainWindow):
    """
    The GUI code of the Chat window of the application
    """
    send_message_requested = Signal(str, str)
    partner_selected = Signal(str)

    def __init__(self, username):
        super().__init__()
        self.username = username
        self.current_partner = None

        self.setWindowTitle(f"TEXTER - {username}")
        self.setGeometry(100, 100, 800, 600)

        # Widgets
        self.contact_list = QListWidget()
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")

        self.send_btn = QPushButton("Send")
        self.status_label = QLabel()

        # Layout
        # Contacts Panel
        contact_panel = QWidget()
        contact_layout = QVBoxLayout(contact_panel)
        contact_layout.addWidget(QLabel("Contacts"))
        contact_layout.addWidget(self.contact_list)

        # Chat Panel
        chat_panel = QWidget()
        chat_layout = QVBoxLayout(chat_panel)
        chat_layout.addWidget(self.status_label)
        chat_layout.addWidget(self.chat_history, 1)

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.message_input, 1)
        input_layout.addWidget(self.send_btn)
        chat_layout.addLayout(input_layout)

        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(contact_panel)
        splitter.addWidget(chat_panel)
        splitter.setSizes([200, 600])

        self.setCentralWidget(splitter)

        # Connections
        self.send_btn.clicked.connect(self.on_send_message_click)
        self.message_input.returnPressed.connect(self.on_send_message_click)
        self.contact_list.currentItemChanged.connect(self.on_partner_select)

        # Contact List Items
        #TODO Add contact list people in the contact list


    def on_send_message_click(self):
        text = self.message_input.text()
        if text and self.current_partner:
            self.send_message_requested.emit(text, self.current_partner)
            self.add_message("Me", text)
            self.message_input.clear()

    def on_partner_select(self, current, previous):
        if current:
            self.current_partner = current.text()
            self.chat_history.clear()
            self.set_status(f"Checking availability of {self.current_partner}...", "blue")
            self.partner_selected.emit(self.current_partner)

    @Slot(str, str)
    def add_message(self, sender: str, text: str):
        self.chat_history.append(f"<b>{sender}:</b> {text}")

    def set_status(self, text: str, color: str = "black"):
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color}")
