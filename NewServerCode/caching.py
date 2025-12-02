from __future__ import annotations

import datetime
import psycopg2
import json
import threading # Import threading

from database import DB_connect


class Caching:
    def __init__(self, db: DB_connect.DB_connect):
        self.db = db
        self.ACTIVEUSERS = {} # { websocket : [ user_id , socket_handler ]}
        self._active_users_lock = threading.Lock() # Add a lock for ACTIVEUSERS

    @staticmethod
    def payload(status: str, message):
        """
        Describes the general payload of each message sent
        :param status: The basic code of a sent message, can be "error", "ok"
        :param message: The extra details that needs to be sent
        :return payload: A JSON object containing the status and message
        """

        payload = {
            "status": status,
            "message": message
        }
        return json.dumps(payload)

    def message_payload(self, sender_user_id: str, receiver_user_id: str, text):
        """
        A sub-json payload definition to send an encrypted text
        """
        text_payload = {
            "recv_user_id": receiver_user_id,
            "text": text,
            "sender_user_id": sender_user_id
        }

        return self.payload("Encrypted", text_payload)

    # --- New thread-safe methods for managing ACTIVEUSERS ---
    def add_active_user(self, websocket, user_id: str, socket_handler=None):
        """Adds a new active user to the dictionary."""
        with self._active_users_lock:
            self.ACTIVEUSERS[websocket] = [user_id, socket_handler]

    def update_active_user_handler(self, websocket, socket_handler):
        """Updates the socket_handler for an existing active user."""
        with self._active_users_lock:
            if websocket in self.ACTIVEUSERS:
                self.ACTIVEUSERS[websocket][1] = socket_handler

    def remove_active_user(self, websocket):
        """Removes an active user from the dictionary."""
        with self._active_users_lock:
            if websocket in self.ACTIVEUSERS:
                del self.ACTIVEUSERS[websocket]

    def get_active_user_info(self, websocket):
        """Retrieves user_id and socket_handler for a given websocket."""
        with self._active_users_lock:
            return self.ACTIVEUSERS.get(websocket)

    def get_active_user_websocket(self, user_id: str):
        """
        Checks if the user is active or not.
        Returns the websocket object if the user is active, otherwise None.
        """
        with self._active_users_lock:
            for ws, (u_id, _) in self.ACTIVEUSERS.items():
                if u_id == user_id:
                    return ws
            return None

    def get_all_active_users_websockets(self):
        """
        Returns a list of all active websocket keys.
        This is useful for iteration, but individual access should still use get_active_user_info.
        """
        with self._active_users_lock:
            return list(self.ACTIVEUSERS.keys())

    # --- End of new thread-safe methods ---

    def check_credentials(self, user_id: str, *password: str) -> bool:
        """
        Queries the database to check for the existence of the user in the registered
        user database.
        :param user_id: The username of the user
        :param password: The password hash of the user
        """

        if not self.db.pool:
            print("Database connection pool is not available. Cannot check credentials.")
            return False

        conn = None
        if password:
            try:
                conn = self.db.pool.getconn()
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM user_info WHERE user_id = %s AND password_hash = %s",
                                (user_id, password[0]))
                    result = cur.fetchone()
                    return result is not None
            except (Exception, psycopg2.DatabaseError) as e:
                print(f"Error checking credentials in database: {e}")
                return False
            finally:
                if conn:
                    self.db.pool.putconn(conn)
        else:
            try:
                conn = self.db.pool.getconn()
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM user_info WHERE user_id = %s",
                                (user_id,))
                    result = cur.fetchone()
                    return result is not None
            except (Exception, psycopg2.DatabaseError) as e:
                print(f"Error checking credentials in database: {e}")
                return False
            finally:
                if conn:
                    self.db.pool.putconn(conn)

    def insert_credentials(self, user_id: str, password: str) -> bool:
        """
        Adds a new user credential to the database and then updates the in-memory cache.
        This operation is thread-safe.
        :param user_id: user_id of the registered user
        :param password: password of the registered user
        :return bool:
        """

        if not self.db.pool:
            print("Database connection pool is not available. Cannot add credential.")
            return False

        conn = None
        try:
            conn = self.db.pool.getconn()
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO user_info (user_id, password_hash) VALUES (%s, %s)",
                    (user_id, password)
                )
                conn.commit()
                return True

        except (Exception, psycopg2.DatabaseError):
            print(f"Error adding credential to database for user '{user_id}'.")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.db.pool.putconn(conn)


    def insert_into_textcache(self, encrypted_text: dict, receiver_id: str, sender_id: str, flag: bool = False) -> bool:
        """
        insert the encrypted text into the text cache database.
        :param encrypted_text: The dictionary containing the encrypted payload.
        :param receiver_id: The receiver's user ID.
        :param sender_id: The sender's user ID.
        :param flag: A boolean flag for the message.
        :return bool:
        """
        if not self.db.pool:
            print("Database connection pool is not available. Cannot add to cache.")
            return False

        conn = None
        try:
            # Convert the dictionary to a JSON string for storage.
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
            print(f"Error adding text to cache for user '{receiver_id}': {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.db.pool.putconn(conn)

    def send_text(self, sender_id: str, receiver_id: str, text: dict, *cache: bool) -> bool:
        """
        Redirect the text to the receiver.
        :param sender_id:
        :param receiver_id:
        :param text: The dictionary containing the encrypted payload.
        :return bool:
        """
        try:
            socket_ws = self.get_active_user_websocket(receiver_id)

            if socket_ws:
                active_user_info = self.get_active_user_info(socket_ws)
                if active_user_info and active_user_info[1]: # active_user_info[1] is the socket_handler
                    socket_handler = active_user_info[1]
                    # message_payload returns a JSON string, we need a dict for the command queue
                    message_dict = json.loads(self.message_payload(sender_id, receiver_id, text))
                    command_payload = {'method': 'send_text', 'args': message_dict}
                    socket_handler.command_queue.put(command_payload)

                    # Only cache if not explicitly told not to (i.e., if cache is empty or False)
                    if not cache or cache[0] is False:
                        self.insert_into_textcache(text, receiver_id, sender_id, True)
                    return True
                else:
                    # User is active, but handler not fully set up or missing
                    if not cache or cache[0] is False:
                        self.insert_into_textcache(text, receiver_id, sender_id)
                    return False
            else:
                # User is not active, cache the message
                self.insert_into_textcache(text, receiver_id, sender_id)
                return False
        except Exception as e:
            print(f"Error in caching.send_text: {e}")
            return False # Ensure a boolean is always returned

    def retrieve_cached_messages(self, receiver_id: str, sender_id: str | None = None):
        """
        Retrieves cached messages for a user.
        If sender_id is provided, it fetches messages only from that sender.
        If sender_id is None, it fetches all unread messages from all senders.
        """
        conn = None
        try:
            conn = self.db.pool.getconn()
            
            senders_to_check = []
            if sender_id:
                senders_to_check.append(sender_id)
            else:
                # Get all distinct senders who have messages for the receiver
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
            if conn:
                conn.rollback()
        finally:
            if conn:
                self.db.pool.putconn(conn)
