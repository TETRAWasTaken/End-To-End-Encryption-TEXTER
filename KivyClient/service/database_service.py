import os
import sqlite3
import pickle
from typing import Dict, Optional, List
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from Client.services.double_ratchet import DoubleRatchetSession

class DatabaseService:
    """
    Manages all interactions with the local SQLite database for a user.

    This class provides a comprehensive API for storing and retrieving all
    user-specific data, including cryptographic keys, session states, contacts,
    and message history. It is designed to be used by a single thread.
    """

    def __init__(self, db_path: str):
        """
        Initializes the DatabaseService.

        Args:
            db_path: The file path to the SQLite database.
        """
        self._db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self, file_key: bytes):
        """
        Connects to the SQLite database.

        Args:
            file_key: A key for database encryption (currently unused).
        """
        self.conn = sqlite3.connect(self._db_path)
        self.conn.row_factory = sqlite3.Row
        print(f"Database connected at {self._db_path}. (Note: Using standard, unencrypted SQLite)")

    def close(self):
        """Closes the database connection if it is open."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def is_connected(self) -> bool:
        """
        Checks if the database connection is currently active.

        Returns:
            True if connected, False otherwise.
        """
        return self.conn is not None

    def create_tables(self):
        """Creates the necessary database tables if they do not already exist."""
        if not self.conn:
            raise ConnectionError("Database is not connected.")
        with self.conn:
            self.conn.execute("CREATE TABLE IF NOT EXISTS keystore (key_name TEXT PRIMARY KEY, key_data BLOB NOT NULL)")
            self.conn.execute("CREATE TABLE IF NOT EXISTS one_time_pre_keys (key_id INTEGER PRIMARY KEY, private_key BLOB NOT NULL)")
            self.conn.execute("CREATE TABLE IF NOT EXISTS sessions (partner_id TEXT PRIMARY KEY, session_data BLOB NOT NULL)")
            self.conn.execute("CREATE TABLE IF NOT EXISTS contacts (partner_id TEXT PRIMARY KEY)")
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    partner_id TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def save_key(self, key_name: str, key_data: bytes):
        """
        Saves or replaces a key in the keystore.

        Args:
            key_name: The unique name of the key.
            key_data: The raw bytes of the key.
        """
        if not self.conn: return
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO keystore (key_name, key_data) VALUES (?, ?)", (key_name, key_data))

    def get_key(self, key_name: str) -> Optional[bytes]:
        """
        Retrieves a key from the keystore.

        Args:
            key_name: The name of the key to retrieve.

        Returns:
            The raw bytes of the key, or None if not found.
        """
        if not self.conn: return None
        cursor = self.conn.execute("SELECT key_data FROM keystore WHERE key_name = ?", (key_name,))
        row = cursor.fetchone()
        return row['key_data'] if row else None

    def save_session(self, partner_id: str, session: DoubleRatchetSession):
        """
        Saves or replaces a Double Ratchet session in the database.

        Args:
            partner_id: The unique identifier of the communication partner.
            session: The DoubleRatchetSession object to save.
        """
        if not self.conn: return
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO sessions (partner_id, session_data) VALUES (?, ?)", (partner_id, pickle.dumps(session)))

    def get_session(self, partner_id: str) -> Optional[DoubleRatchetSession]:
        """
        Retrieves a Double Ratchet session from the database.

        Args:
            partner_id: The unique identifier of the communication partner.

        Returns:
            The deserialized DoubleRatchetSession object, or None if not found.
        """
        if not self.conn: return None
        cursor = self.conn.execute("SELECT session_data FROM sessions WHERE partner_id = ?", (partner_id,))
        row = cursor.fetchone()
        return pickle.loads(row['session_data']) if row else None

    def get_all_sessions(self) -> Dict[str, DoubleRatchetSession]:
        """
        Retrieves all Double Ratchet sessions from the database.

        Returns:
            A dictionary mapping partner IDs to their DoubleRatchetSession objects.
        """
        if not self.conn: return {}
        cursor = self.conn.execute("SELECT partner_id, session_data FROM sessions")
        return {row['partner_id']: pickle.loads(row['session_data']) for row in cursor.fetchall()}

    def save_opks(self, opks: Dict[int, x25519.X25519PrivateKey]):
        """
        Saves a dictionary of one-time pre-keys to the database, replacing any
        existing ones.

        Args:
            opks: A dictionary mapping key IDs to private key objects.
        """
        if not self.conn: return
        opk_list = [
            (key_id, opk_priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
            for key_id, opk_priv in opks.items()
        ]
        with self.conn:
            self.conn.execute("DELETE FROM one_time_pre_keys")
            self.conn.executemany("INSERT INTO one_time_pre_keys (key_id, private_key) VALUES (?, ?)", opk_list)

    def get_all_opks(self) -> Dict[int, x25519.X25519PrivateKey]:
        """
        Retrieves all one-time pre-keys from the database.

        Returns:
            A dictionary mapping key IDs to deserialized private key objects.
        """
        if not self.conn: return {}
        cursor = self.conn.execute("SELECT key_id, private_key FROM one_time_pre_keys")
        return {row['key_id']: x25519.X25519PrivateKey.from_private_bytes(row['private_key']) for row in cursor.fetchall()}

    def pop_opk(self, key_id: int) -> Optional[x25519.X25519PrivateKey]:
        """
        Atomically retrieves and deletes a one-time pre-key from the database.

        Args:
            key_id: The ID of the key to retrieve and delete.

        Returns:
            The private key object, or None if not found.
        """
        if not self.conn: return None
        with self.conn:
            cursor = self.conn.execute("SELECT private_key FROM one_time_pre_keys WHERE key_id = ?", (key_id,))
            row = cursor.fetchone()
            if row:
                self.conn.execute("DELETE FROM one_time_pre_keys WHERE key_id = ?", (key_id,))
                return x25519.X25519PrivateKey.from_private_bytes(row['private_key'])
        return None

    def save_contacts(self, contacts: List[str]):
        """
        Saves a list of contacts to the database, replacing any existing list.

        Args:
            contacts: A list of partner IDs.
        """
        if not self.conn: return
        with self.conn:
            self.conn.execute("DELETE FROM contacts")
            self.conn.executemany("INSERT INTO contacts (partner_id) VALUES (?)", [(c,) for c in contacts])

    def get_all_contacts(self) -> List[str]:
        """
        Retrieves all contacts from the database.

        Returns:
            A list of partner IDs.
        """
        if not self.conn: return []
        cursor = self.conn.execute("SELECT partner_id FROM contacts")
        return [row['partner_id'] for row in cursor.fetchall()]

    def get_salt(self) -> Optional[bytes]:
        """
        Retrieves the PBKDF2 salt from the keystore.

        Returns:
            The salt as bytes, or None if not found.
        """
        return self.get_key("pbkdf2_salt")

    def save_salt(self, salt: bytes):
        """
        Saves the PBKDF2 salt to the keystore.

        Args:
            salt: The salt to save.
        """
        self.save_key("pbkdf2_salt", salt)

    def add_message(self, partner_id: str, sender: str, message: str):
        """
        Adds a message to the chat history.

        Args:
            partner_id: The ID of the communication partner.
            sender: The ID of the message sender.
            message: The content of the message.
        """
        if not self.conn: return
        with self.conn:
            self.conn.execute("INSERT INTO messages (partner_id, sender, message) VALUES (?, ?, ?)", (partner_id, sender, message))

    def get_messages(self, partner_id: str) -> List[Dict]:
        """
        Retrieves the message history for a given partner.

        Args:
            partner_id: The ID of the communication partner.

        Returns:
            A list of message dictionaries, ordered by timestamp.
        """
        if not self.conn: return []
        cursor = self.conn.execute("SELECT sender, message, timestamp FROM messages WHERE partner_id = ? ORDER BY timestamp ASC", (partner_id,))
        return [dict(row) for row in cursor.fetchall()]