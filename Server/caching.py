from __future__ import annotations

import datetime
import psycopg2
import json
import threading

from database import DB_connect


class caching:
    """
    Manages user sessions, message caching, and database interactions for the
    secure chat server.

    This class handles the caching of active user connections, credentials
    verification, and the storage and retrieval of messages. It provides a
    thread-safe mechanism for managing shared resources like the active user
    dictionary and the database connection pool.
    """
    def __init__(self, db: DB_connect.DB_connect):
        """
        Initializes the caching instance.

        Args:
            db: An instance of DB_connect for database connection management.
        """
        self.db = db
        self.ACTIVEUSERS = {}  # { websocket : [ user_id , socket_handler ]}
        self._active_users_lock = threading.Lock()

    @staticmethod
    def payload(status: str, message):
        """
        Creates a JSON payload for sending messages to clients.

        Args:
            status: The status of the message (e.g., "Encrypted", "User_Select").
            message: The content of the message.

        Returns:
            A JSON string representing the payload.
        """
        payload = {
            "status": status,
            "message": message
        }
        return json.dumps(payload)

    def message_payload(self, sender_user_id: str, receiver_user_id: str, text):
        """
        Creates a specific payload for an encrypted text message.

        Args:
            sender_user_id: The user ID of the sender.
            receiver_user_id: The user ID of the receiver.
            text: The encrypted message content.

        Returns:
            A JSON string representing the encrypted message payload.
        """
        text_payload = {
            "recv_user_id": receiver_user_id,
            "text": text,
            "sender_user_id": sender_user_id
        }
        return self.payload("Encrypted", text_payload)

    def add_active_user(self, websocket, user_id: str, socket_handler=None):
        """
        Adds a user to the dictionary of active users.

        Args:
            websocket: The WebSocket connection object for the user.
            user_id: The user's unique identifier.
            socket_handler: The handler for the user's WebSocket connection.
        """
        with self._active_users_lock:
            self.ACTIVEUSERS[websocket] = [user_id, socket_handler]

    def update_active_user_handler(self, websocket, socket_handler):
        """
        Updates the socket handler for an active user.

        Args:
            websocket: The WebSocket connection object for the user.
            socket_handler: The new socket handler.
        """
        with self._active_users_lock:
            if websocket in self.ACTIVEUSERS:
                self.ACTIVEUSERS[websocket][1] = socket_handler

    def remove_active_user(self, websocket):
        """
        Removes a user from the dictionary of active users.

        Args:
            websocket: The WebSocket connection object for the user.
        """
        with self._active_users_lock:
            if websocket in self.ACTIVEUSERS:
                del self.ACTIVEUSERS[websocket]

    def get_active_user_info(self, websocket):
        """
        Retrieves information about an active user.

        Args:
            websocket: The WebSocket connection object for the user.

        Returns:
            A list containing the user's ID and socket handler, or None if not found.
        """
        with self._active_users_lock:
            return self.ACTIVEUSERS.get(websocket)

    def get_active_user_websocket(self, user_id: str):
        """
        Retrieves the WebSocket connection for an active user.

        Args:
            user_id: The user's unique identifier.

        Returns:
            The WebSocket connection object, or None if the user is not active.
        """
        with self._active_users_lock:
            for ws, (u_id, _) in self.ACTIVEUSERS.items():
                if u_id == user_id:
                    return ws
            return None

    def get_all_active_users_websockets(self):
        """
        Retrieves a list of all active WebSocket connections.

        Returns:
            A list of WebSocket connection objects.
        """
        with self._active_users_lock:
            return list(self.ACTIVEUSERS.keys())

    def check_credentials(self, user_id: str, *password: str) -> bool:
        """
        Verifies a user's credentials against the database.

        Args:
            user_id: The user's unique identifier.
            password: The user's password (optional).

        Returns:
            True if the credentials are valid, False otherwise.
        """
        if not self.db.pool:
            print("Database connection pool is not available.")
            return False

        conn = None
        if password:
            try:
                conn = self.db.pool.getconn()
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM user_info WHERE user_id = %s AND password_hash = %s",
                                (user_id, password[0]))
                    return cur.fetchone() is not None
            except (Exception, psycopg2.DatabaseError) as e:
                print(f"Error checking credentials: {e}")
                return False
            finally:
                if conn: self.db.pool.putconn(conn)
        else:
            try:
                conn = self.db.pool.getconn()
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM user_info WHERE user_id = %s", (user_id,))
                    return cur.fetchone() is not None
            except (Exception, psycopg2.DatabaseError) as e:
                print(f"Error checking credentials: {e}")
                return False
            finally:
                if conn: self.db.pool.putconn(conn)

    def insert_credentials(self, user_id: str, password: str) -> bool:
        """
        Inserts new user credentials into the database.

        Args:
            user_id: The user's unique identifier.
            password: The user's password.

        Returns:
            True if the insertion was successful, False otherwise.
        """
        if not self.db.pool: return False
        conn = None
        try:
            conn = self.db.pool.getconn()
            with conn.cursor() as cur:
                cur.execute("INSERT INTO user_info (user_id, password_hash) VALUES (%s, %s)", (user_id, password))
                conn.commit()
                return True
        except (Exception, psycopg2.DatabaseError):
            if conn: conn.rollback()
            return False
        finally:
            if conn: self.db.pool.putconn(conn)

    def insert_into_textcache(self, encrypted_text: dict, receiver_id: str, sender_id: str, flag: bool = False) -> bool:
        """
        Caches a message in the database.

        Args:
            encrypted_text: The encrypted message content.
            receiver_id: The user ID of the receiver.
            sender_id: The user ID of the sender.
            flag: A boolean flag indicating the message status.

        Returns:
            True if the message was cached successfully, False otherwise.
        """
        if not self.db.pool: return False
        conn = None
        try:
            encrypted_text_str = json.dumps(encrypted_text)
            conn = self.db.pool.getconn()
            with conn.cursor() as cur:
                if flag:
                    cur.execute(
                        "INSERT INTO text_cache (text_cache, receiver_id, sender_id, time_stamp_creation, flag) VALUES (%s, %s, %s, %s, %s)",
                        (encrypted_text_str, receiver_id, sender_id, datetime.datetime.now(), True)
                    )
                else:
                    cur.execute(
                        "INSERT INTO text_cache (text_cache, receiver_id, sender_id, time_stamp_creation) VALUES (%s, %s, %s, %s)",
                        (encrypted_text_str, receiver_id, sender_id, datetime.datetime.now())
                    )
                conn.commit()
                return True
        except (Exception, psycopg2.DatabaseError) as e:
            print(f"Error caching message: {e}")
            if conn: conn.rollback()
            return False
        finally:
            if conn: self.db.pool.putconn(conn)

    def send_text(self, sender_id: str, receiver_id: str, text: dict, *cache: bool) -> bool:
        """
        Redirects a text message to the recipient's socket handler or caches it.

        This method attempts to find the recipient in the active users list. If
        found, it queues the message to be sent. If not, it caches the message
        in the database for later retrieval.

        Args:
            sender_id: The user ID of the message sender.
            receiver_id: The user ID of the message recipient.
            text: The encrypted message payload.
            cache: An optional boolean to control caching behavior.

        Returns:
            True if the message was sent to an active user, False if the user
            was offline and the message was cached.
        """
        try:
            socket_ws = self.get_active_user_websocket(receiver_id)

            if socket_ws:
                active_user_info = self.get_active_user_info(socket_ws)
                if active_user_info and active_user_info[1]:
                    socket_handler = active_user_info[1]
                    message_dict = json.loads(self.message_payload(sender_id, receiver_id, text))
                    command_payload = {'method': 'send_text', 'args': message_dict}

                    if hasattr(socket_handler, '_queue_external_command'):
                        socket_handler.queue_external_command(command_payload)
                    else:
                        socket_handler.command_queue.put(command_payload)

                    if not cache or cache[0] is False:
                        self.insert_into_textcache(text, receiver_id, sender_id, True)
                    return True
                else:
                    if not cache or cache[0] is False:
                        self.insert_into_textcache(text, receiver_id, sender_id)
                    return False
            else:
                self.insert_into_textcache(text, receiver_id, sender_id)
                return False
        except Exception as e:
            print(f"Error in caching.send_text: {e}")
            return False

    def retrieve_cached_messages(self, receiver_id: str, sender_id: str | None = None):
        """
        Retrieves and sends cached messages to a user.

        Args:
            receiver_id: The user ID of the receiver.
            sender_id: The user ID of the sender (optional). If not provided,
                       messages from all senders are retrieved.
        """
        conn = None
        try:
            conn = self.db.pool.getconn()
            senders_to_check = []
            if sender_id:
                senders_to_check.append(sender_id)
            else:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT DISTINCT sender_id FROM text_cache WHERE receiver_id = %s AND flag = FALSE",
                        (receiver_id,)
                    )
                    senders_to_check = [row[0] for row in cur.fetchall()]

            if not senders_to_check:
                return

            print(f"Checking cached messages for {receiver_id} from sender(s): {senders_to_check}")

            with conn.cursor() as cur:
                for a_sender_id in senders_to_check:
                    cur.execute(
                        "SELECT id, text_cache, time_stamp_creation FROM text_cache WHERE receiver_id = %s AND sender_id = %s AND flag = FALSE ORDER BY time_stamp_creation",
                        (receiver_id, a_sender_id)
                    )
                    results = cur.fetchall()

                    if not results:
                        continue

                    with conn.cursor() as update_cur:
                        for msg_id, text_cache, time_stamp in results:
                            text_dict = json.loads(text_cache)
                            if self.send_text(a_sender_id, receiver_id, text_dict, True):
                                update_cur.execute(
                                    "UPDATE text_cache SET flag = TRUE, time_stamp_last_usage = %s WHERE id=%s",
                                    (datetime.datetime.now(), msg_id)
                                )
                            else:
                                print(f"Error while sending cached text from {a_sender_id} to {receiver_id}.")
            conn.commit()

        except Exception as e:
            print(f"Error in caching.retrieve_cached_messages: {e}")
            if conn: conn.rollback()
        finally:
            if conn: self.db.pool.putconn(conn)