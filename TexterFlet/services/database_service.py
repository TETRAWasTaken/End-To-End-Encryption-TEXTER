import os
import sqlite3
import pickle
from typing import Dict, Optional, List
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from services.double_ratchet import DoubleRatchetSession

class DatabaseService:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self, file_key: bytes):
        # NOTE: file_key is accepted but not used here as we are using standard SQLite.
        self.conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        print(f"Database connected at {self._db_path}.")

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def is_connected(self) -> bool:
        return self.conn is not None

    def create_tables(self):
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
        if not self.conn: return
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO keystore (key_name, key_data) VALUES (?, ?)", (key_name, key_data))

    def get_key(self, key_name: str) -> Optional[bytes]:
        if not self.conn: return None
        cursor = self.conn.execute("SELECT key_data FROM keystore WHERE key_name = ?", (key_name,))
        row = cursor.fetchone()
        return row['key_data'] if row else None

    def save_session(self, partner_id: str, session: DoubleRatchetSession):
        if not self.conn: return
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO sessions (partner_id, session_data) VALUES (?, ?)", (partner_id, pickle.dumps(session)))

    def get_session(self, partner_id: str) -> Optional[DoubleRatchetSession]:
        if not self.conn: return None
        cursor = self.conn.execute("SELECT session_data FROM sessions WHERE partner_id = ?", (partner_id,))
        row = cursor.fetchone()
        return pickle.loads(row['session_data']) if row else None

    def get_all_sessions(self) -> Dict[str, DoubleRatchetSession]:
        if not self.conn: return {}
        cursor = self.conn.execute("SELECT partner_id, session_data FROM sessions")
        return {row['partner_id']: pickle.loads(row['session_data']) for row in cursor.fetchall()}

    def save_opks(self, opks: Dict[int, x25519.X25519PrivateKey]):
        if not self.conn: return
        opk_list = [
            (key_id, opk_priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
            for key_id, opk_priv in opks.items()
        ]
        with self.conn:
            self.conn.execute("DELETE FROM one_time_pre_keys")
            self.conn.executemany("INSERT INTO one_time_pre_keys (key_id, private_key) VALUES (?, ?)", opk_list)

    def get_all_opks(self) -> Dict[int, x25519.X25519PrivateKey]:
        if not self.conn: return {}
        cursor = self.conn.execute("SELECT key_id, private_key FROM one_time_pre_keys")
        return {row['key_id']: x25519.X25519PrivateKey.from_private_bytes(row['private_key']) for row in cursor.fetchall()}

    def pop_opk(self, key_id: int) -> Optional[x25519.X25519PrivateKey]:
        if not self.conn: return None
        with self.conn:
            cursor = self.conn.execute("SELECT private_key FROM one_time_pre_keys WHERE key_id = ?", (key_id,))
            row = cursor.fetchone()
            if row:
                self.conn.execute("DELETE FROM one_time_pre_keys WHERE key_id = ?", (key_id,))
                return x25519.X25519PrivateKey.from_private_bytes(row['private_key'])
        return None

    def save_contacts(self, contacts: List[str]):
        if not self.conn: return
        with self.conn:
            self.conn.execute("DELETE FROM contacts")
            self.conn.executemany("INSERT INTO contacts (partner_id) VALUES (?)", [(c,) for c in contacts])

    def get_all_contacts(self) -> List[str]:
        if not self.conn: return []
        cursor = self.conn.execute("SELECT partner_id FROM contacts")
        return [row['partner_id'] for row in cursor.fetchall()]

    def get_salt(self) -> Optional[bytes]:
        return self.get_key("pbkdf2_salt")

    def save_salt(self, salt: bytes):
        self.save_key("pbkdf2_salt", salt)

    def add_message(self, partner_id: str, sender: str, message: str):
        if not self.conn: return
        with self.conn:
            self.conn.execute("INSERT INTO messages (partner_id, sender, message) VALUES (?, ?, ?)", (partner_id, sender, message))

    def get_messages(self, partner_id: str) -> List[Dict]:
        if not self.conn: return []
        cursor = self.conn.execute("SELECT sender, message, timestamp FROM messages WHERE partner_id = ? ORDER BY timestamp ASC", (partner_id,))
        return [dict(row) for row in cursor.fetchall()]