from PySide6.QtWidgets import (QMainWindow, QVBoxLayout, QWidget,
                               QTextEdit, QLineEdit, QPushButton,
                               QSplitter, QListWidget, QLabel, QHBoxLayout, QTabWidget)
from PySide6.QtCore import Slot, Signal, Qt
from typing import List, Dict

class ChatWindow(QMainWindow):
    """
    The GUI code of the Chat window of the application
    """
    send_message_requested = Signal(str, str)
    partner_selected = Signal(str)
    friend_request_sent = Signal(str)
    friend_request_accepted = Signal(str)

    def __init__(self, username):
        super().__init__()
        self.username = username
        self.current_partner = None

        self.setWindowTitle(f"TEXTER - {username}")
        self.setGeometry(100, 100, 800, 600)

        # Create a tab widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Create Chat Tab
        self.chat_tab = QWidget()
        self.tabs.addTab(self.chat_tab, "Chat")
        self.setup_chat_ui()

        # Create Friend Request Tab
        self.friend_request_tab = QWidget()
        self.tabs.addTab(self.friend_request_tab, "Friend Requests")
        self.setup_friend_request_ui()

        # Connections
        self.send_btn.clicked.connect(self.on_send_message_click)
        self.message_input.returnPressed.connect(self.on_send_message_click)
        self.contact_list.currentItemChanged.connect(self.on_partner_select)
        self.add_partner_btn.clicked.connect(self.on_add_partner_click)
        self.send_friend_request_btn.clicked.connect(self.on_send_friend_request_click)

    def setup_chat_ui(self):
        # Widgets
        self.contact_list = QListWidget()
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")

        self.send_btn = QPushButton("Send")
        self.status_label = QLabel()
        self.status_label.setObjectName("statusLabel")

        self.partner_input = QLineEdit()
        self.partner_input.setPlaceholderText("Enter partner's username")
        self.add_partner_btn = QPushButton("Chat")

        # Layout
        contact_panel = QWidget()
        contact_layout = QVBoxLayout(contact_panel)
        contact_layout.addWidget(QLabel("Contacts"))
        
        partner_input_layout = QHBoxLayout()
        partner_input_layout.addWidget(self.partner_input)
        partner_input_layout.addWidget(self.add_partner_btn)
        contact_layout.addLayout(partner_input_layout)

        contact_layout.addWidget(self.contact_list)

        chat_panel = QWidget()
        chat_layout = QVBoxLayout(chat_panel)
        chat_layout.addWidget(self.status_label)
        chat_layout.addWidget(self.chat_history, 1)

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.message_input, 1)
        input_layout.addWidget(self.send_btn)
        chat_layout.addLayout(input_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(contact_panel)
        splitter.addWidget(chat_panel)
        splitter.setSizes([200, 600])

        chat_tab_layout = QVBoxLayout(self.chat_tab)
        chat_tab_layout.addWidget(splitter)

    def setup_friend_request_ui(self):
        layout = QVBoxLayout(self.friend_request_tab)
        
        self.friend_username_input = QLineEdit()
        self.friend_username_input.setPlaceholderText("Enter username to send friend request")
        
        self.send_friend_request_btn = QPushButton("Send Friend Request")
        
        self.friend_request_status_label = QLabel()
        
        layout.addWidget(self.friend_username_input)
        layout.addWidget(self.send_friend_request_btn)
        layout.addWidget(self.friend_request_status_label)
        layout.addStretch()

    def on_send_friend_request_click(self):
        friend_username = self.friend_username_input.text().strip()
        if friend_username:
            self.friend_request_sent.emit(friend_username)
            self.friend_username_input.clear()

    def on_send_message_click(self):
        text = self.message_input.text()
        if text and self.current_partner:
            self.send_message_requested.emit(self.current_partner, text)
            self.add_message(self.username, text)
            self.message_input.clear()

    def on_add_partner_click(self):
        partner_name = self.partner_input.text().strip()
        if partner_name and partner_name != self.username:
            if not self.contact_list.findItems(partner_name, Qt.MatchFlag.MatchExactly):
                self.contact_list.addItem(partner_name)

            items = self.contact_list.findItems(partner_name, Qt.MatchFlag.MatchExactly)
            if items:
                self.contact_list.setCurrentItem(items[0])
            
            self.partner_input.clear()

    def on_partner_select(self, current, previous):
        if current:
            self.select_partner(current.text())
    
    def select_partner(self, partner_name: str):
        if partner_name and partner_name != self.current_partner:
            self.current_partner = partner_name
            self.chat_history.clear()
            self.set_status(f"Checking availability of {self.current_partner}...", "blue")
            self.set_input_enabled(False)
            self.partner_selected.emit(self.current_partner)

    @Slot(str, str)
    def add_message(self, sender: str, text: str):
        display_sender = "Me" if sender == self.username else sender
        self.chat_history.append(f"<b>{display_sender}:</b> {text}")

    def load_chat_history(self, history: List[Dict]):
        self.chat_history.clear()
        for item in history:
            self.add_message(item['sender'], item['message'])

    def set_status(self, text: str, color: str = "black"):
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color}")

    @Slot(bool)
    def set_input_enabled(self, enabled: bool):
        self.message_input.setEnabled(enabled)
        self.send_btn.setEnabled(enabled)

    def add_friend_request_notification(self, from_user: str):
        notification_widget = QWidget()
        layout = QHBoxLayout(notification_widget)
        
        label = QLabel(f"New friend request from: {from_user}")
        accept_btn = QPushButton("Accept")
        
        layout.addWidget(label)
        layout.addWidget(accept_btn)
        
        accept_btn.clicked.connect(lambda: self.on_accept_friend_request(from_user, notification_widget))
        
        self.friend_request_tab.layout().insertWidget(self.friend_request_tab.layout().count() - 1, notification_widget)

    def on_accept_friend_request(self, from_user: str, widget: QWidget):
        self.friend_request_accepted.emit(from_user)
        widget.deleteLater()

    def show_friend_request_status(self, status: str):
        if status == "sent":
            self.friend_request_status_label.setText("Friend request sent successfully.")
            self.friend_request_status_label.setStyleSheet("color: #A3BE8C;") # Nord Frost - Green
        elif status == "failed":
            self.friend_request_status_label.setText("Failed to send friend request. User may not exist or a request is already pending.")
            self.friend_request_status_label.setStyleSheet("color: #BF616A;") # Nord Frost - Red
        else:
            self.friend_request_status_label.setText(f"Friend request status: {status}")
            self.friend_request_status_label.setStyleSheet("color: #D8DEE9;") # Nord Snow Storm
    
    def add_contact(self, contact_name: str):
        """Adds a single contact to the list if it doesn't already exist."""
        if not self.contact_list.findItems(contact_name, Qt.MatchFlag.MatchExactly):
            self.contact_list.addItem(contact_name)
