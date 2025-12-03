import os
import sqlite3
import pickle
import json
from typing import Dict, Optional, List
import datetime

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from Client.services.double_ratchet import DoubleRatchetSession


class DatabaseService:
    """
    Manages all interactions with the local, SQLite database.
    This is NOT thread-safe by default. It should be accessed from a single
    thread or have external locking.
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self, file_key: bytes):
        """
        Connects to the standard SQLite database.
        NOTE: This is a placeholder and does not use SQLCipher.
        """
        self.conn = sqlite3.connect(self._db_path)
        self.conn.row_factory = sqlite3.Row
        print(f"Database connected at {self._db_path}. (Note: Using standard, unencrypted SQLite)")

    def close(self):
        """Closes the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def is_connected(self) -> bool:
        return self.conn is not None

    def create_tables(self):
        """Creates the necessary tables if they don't exist."""
        if not self.conn:
            raise ConnectionError("Database is not connected.")

        with self.conn:
            # Stores long-term identity and pre-keys
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS keystore (
                    key_name TEXT PRIMARY KEY,
                    key_data BLOB NOT NULL
                )
            """)

            # Stores one-time pre-keys
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS one_time_pre_keys (
                    key_id INTEGER PRIMARY KEY,
                    private_key BLOB NOT NULL
                )
            """)

            # Stores Double Ratchet sessions per partner
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    partner_id TEXT PRIMARY KEY,
                    session_data BLOB NOT NULL
                )
            """)

            # Stores contacts
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS contacts (
                    partner_id TEXT PRIMARY KEY
                )
            """)
            
            # Stores chat history
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    partner_id TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

    # --- Keystore Methods ---
    def save_key(self, key_name: str, key_data: bytes):
        if not self.conn: return
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO keystore (key_name, key_data) VALUES (?, ?)",
                (key_name, key_data)
            )

    def get_key(self, key_name: str) -> Optional[bytes]:
        if not self.conn: return None
        cursor = self.conn.execute("SELECT key_data FROM keystore WHERE key_name = ?", (key_name,))
        row = cursor.fetchone()
        return row['key_data'] if row else None

    # --- Session Methods ---
    def save_session(self, partner_id: str, session: DoubleRatchetSession):
        if not self.conn: return
        session_bytes = pickle.dumps(session)
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO sessions (partner_id, session_data) VALUES (?, ?)",
                (partner_id, session_bytes)
            )

    def get_session(self, partner_id: str) -> Optional[DoubleRatchetSession]:
        if not self.conn: return None
        cursor = self.conn.execute("SELECT session_data FROM sessions WHERE partner_id = ?", (partner_id,))
        row = cursor.fetchone()
        if row:
            return pickle.loads(row['session_data'])
        return None

    def get_all_sessions(self) -> Dict[str, DoubleRatchetSession]:
        if not self.conn: return {}
        sessions = {}
        cursor = self.conn.execute("SELECT partner_id, session_data FROM sessions")
        for row in cursor.fetchall():
            sessions[row['partner_id']] = pickle.loads(row['session_data'])
        return sessions

    # --- OPK Methods ---
    def save_opks(self, opks: Dict[int, x25519.X25519PrivateKey]):
        if not self.conn: return
        opk_list = []
        for key_id, opk_priv in opks.items():
            opk_bytes = opk_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            opk_list.append((key_id, opk_bytes))

        with self.conn:
            self.conn.execute("DELETE FROM one_time_pre_keys")
            self.conn.executemany("INSERT INTO one_time_pre_keys (key_id, private_key) VALUES (?, ?)", opk_list)

    def get_all_opks(self) -> Dict[int, x25519.X25519PrivateKey]:
        if not self.conn: return {}
        opks = {}
        cursor = self.conn.execute("SELECT key_id, private_key FROM one_time_pre_keys")
        for row in cursor.fetchall():
            opks[row['key_id']] = x25519.X25519PrivateKey.from_private_bytes(row['private_key'])
        return opks

    def pop_opk(self, key_id: int) -> Optional[x25519.X25519PrivateKey]:
        if not self.conn: return None
        with self.conn:
            cursor = self.conn.execute("SELECT private_key FROM one_time_pre_keys WHERE key_id = ?", (key_id,))
            row = cursor.fetchone()
            if row:
                self.conn.execute("DELETE FROM one_time_pre_keys WHERE key_id = ?", (key_id,))
                return x25519.X25519PrivateKey.from_private_bytes(row['private_key'])
        return None

    # --- Contact Methods ---
    def save_contacts(self, contacts: List[str]):
        if not self.conn: return
        contact_list = [(contact,) for contact in contacts]
        with self.conn:
            self.conn.execute("DELETE FROM contacts")
            self.conn.executemany("INSERT INTO contacts (partner_id) VALUES (?)", contact_list)

    def get_all_contacts(self) -> List[str]:
        if not self.conn: return []
        cursor = self.conn.execute("SELECT partner_id FROM contacts")
        return [row['partner_id'] for row in cursor.fetchall()]

    def get_salt(self) -> Optional[bytes]:
        return self.get_key("pbkdf2_salt")

    def save_salt(self, salt: bytes):
        self.save_key("pbkdf2_salt", salt)

    # --- Message History Methods ---
    def add_message(self, partner_id: str, sender: str, message: str):
        if not self.conn: return
        with self.conn:
            self.conn.execute(
                "INSERT INTO messages (partner_id, sender, message) VALUES (?, ?, ?)",
                (partner_id, sender, message)
            )

    def get_messages(self, partner_id: str) -> List[Dict]:
        if not self.conn: return []
        cursor = self.conn.execute(
            "SELECT sender, message, timestamp FROM messages WHERE partner_id = ? ORDER BY timestamp ASC",
            (partner_id,)
        )
        return [dict(row) for row in cursor.fetchall()]
