from __future__ import annotations

import datetime
import psycopg2
import json
import threading # Import threading

from database import DB_connect


class caching:
    def __init__(self, DB: DB_connect.DB_connect, cacheDB: DB_connect.DB_connect):
        print("Initialising Caching system")
        self.DB = DB
        self.cacheDB = cacheDB
        self.ACTIVEUSERS = {} # { websocket : [ user_id , socket_handler ]}
        self._active_users_lock = threading.Lock() # Add a lock for ACTIVEUSERS

    @staticmethod
    def payload(status: str, message: str | dict):
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

    @staticmethod
    def message_payload(self, sender_user_id: str, receiver_user_id: str, text): # Removed staticmethod
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

    # The old check_ACTIVEUSER is replaced by get_active_user_websocket.
    # If you still need a method named check_ACTIVEUSER, you can alias it:
    # check_ACTIVEUSER = get_active_user_websocket

    def check_credentials(self, user_id: str, *password: str) -> bool:
        """
        Queries the database to check for the existence of the user in the registered
        user database.
        :param user_id: The username of the user
        :param password: The password hash of the user
        """

        if not self.DB.pool:
            print("Database connection pool is not available. Cannot check credentials.")
            return False

        conn = None
        if password:
            try:
                conn = self.DB.pool.getconn()
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM user_info WHERE user_id = %s AND password = %s",
                                (user_id, password[0]))
                    result = cur.fetchone()
                    return result is not None
            except (Exception, psycopg2.DatabaseError) as e:
                print(f"Error checking credentials in database: {e}")
                return False
            finally:
                if conn:
                    self.DB.pool.putconn(conn)
        else:
            try:
                conn = self.DB.pool.getconn()
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
                    self.DB.pool.putconn(conn)

    def insert_credentials(self, user_id: str, password: str) -> bool:
        """
        Adds a new user credential to the database and then updates the in-memory cache.
        This operation is thread-safe.
        :param user_id: user_id of the registered user
        :param password: password of the registered user
        :return bool:
        """

        if not self.DB.pool:
            print("Database connection pool is not available. Cannot add credential.")
            return False

        conn = None
        try:
            conn = self.DB.pool.getconn()
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO user_info (user_id, password) VALUES (%s, %s)",
                    (user_id, password)
                )
                conn.commit()
                print(f"New user '{user_id}' credentials saved to database.")
                return True

        except (Exception, psycopg2.DatabaseError):
            print(f"Error adding credential to database for user '{user_id}'.")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.DB.pool.putconn(conn)


    def insert_into_textcache(self, Encrypted_text: bytes, receiver_id: str, sender_id: str, flag: bool = False) -> bool:
        """
        insert the encrypted text into the text cache database.
        :param Encrypted_text:
        :param receiver_id:
        :param sender_id:
        :return bool:
        """
        if not self.cacheDB.pool:
            print("Database connection pool is not available. Cannot add credential.")
            return False

        conn = None
        try:
            if flag:
                conn = self.cacheDB.pool.getconn()
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO text_cache (text_cache, receiver_id, sender_id, time_stamp_creation, flag) VALUES (%s, %s, %s, %s)",
                        (Encrypted_text, receiver_id, sender_id, datetime.datetime.now(), True)
                    )
                    conn.commit()
                    print(f"New text '{Encrypted_text}' saved to database.")
                    return True

            else:
                conn = self.cacheDB.pool.getconn()
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO text_cache (text_cache, receiver_id, sender_id, time_stamp_creation) VALUES (%s, %s, %s, %s)",
                        (Encrypted_text, receiver_id, sender_id, datetime.datetime.now())
                    )
                    conn.commit()
                    print(f"New text '{Encrypted_text}' saved to database.")
                    return True

        except (Exception, psycopg2.DatabaseError):
            print(f"Error adding credential to database for user '{receiver_id}'.")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.cacheDB.pool.putconn(conn)

    def send_text(self, sender_id: str, receiver_id: str, text: bytes, *cache: bool) -> bool:
        """
        Redirect the text to the receiver.
        :param sender_id:
        :param receiver_id:
        :param text:
        :return bool:
        """
        try:
            socket_ws = self.get_active_user_websocket(receiver_id)

            if socket_ws:
                active_user_info = self.get_active_user_info(socket_ws)
                if active_user_info and active_user_info[1]: # active_user_info[1] is the socket_handler
                    socket_handler = active_user_info[1]
                    command_payload = {'method': 'send_text',
                                       'args': json.loads(self.message_payload(self, sender_id, receiver_id, text))}
                    socket_handler.command_queue.put(command_payload)

                    # Only cache if not explicitly told not to (i.e., if cache is empty or False)
                    if not cache or cache[0] is False:
                        self.insert_into_textcache(text, sender_id, receiver_id, True)
                    return True
                else:
                    # User is active, but handler not fully set up or missing (shouldn't happen with proper flow)
                    if not cache or cache[0] is False:
                        self.insert_into_textcache(text, sender_id, receiver_id)
                    return False
            else:
                # User is not active, cache the message
                self.insert_into_textcache(text, sender_id, receiver_id)
                return False
        except Exception as e:
            print(f"Error in caching.send_text: {e}")
            return False # Ensure a boolean is always returned

    def retrieve_text_cache(self, sender_id: str, receiver_id: str):
        """
        Retrieve the text cache from the database.
        and pushes the text to the client.
        """
        try:
            conn = self.cacheDB.pool.getconn()
            with conn.cursor() as cur:
                cur.execute("SELECT text_cache, time_stamp_creation FROM text_cache WHERE receiver_id = %s AND sender_id = %s AND flag = %s ORDER BY time_stamp_creation DESC",
                            (receiver_id, sender_id, False))
                result = cur.fetchall()

            if result:
                for i in result:
                    # Pass True to send_text to indicate it's from cache, so it doesn't re-cache
                    if self.send_text(sender_id, receiver_id, i[0], True):
                        cur.execute("UPDATE text_cache SET flag = %s, time_stamp_last_usage = %s WHERE time_stamp_creation = %s AND text_cache = %s",
                                    (True, datetime.datetime.now(), i[1], i[0]))
                    else:
                        print("Error while sending text to client.")
                conn.commit() # Commit updates after the loop
            else:
                print("No text found in cache.")

        except Exception as e:
            print(f"Error in caching.retrieve_text_cache: {e}")
        finally:
            if conn:
                self.cacheDB.pool.putconn(conn)
