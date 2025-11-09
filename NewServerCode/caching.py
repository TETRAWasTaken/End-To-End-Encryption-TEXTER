from __future__ import annotations

import datetime
import psycopg2
import json

from X3DH import DB_connect


class caching:
    def __init__(self, DB: DB_connect.DB_connect, cacheDB: DB_connect.DB_connect):
        print("Initialising Caching system")
        self.DB = DB
        self.cacheDB = cacheDB
        self.ACTIVEUSERS = {} # { websocket : [ user_id , socket_handler ]}

    @staticmethod
    def payload(status: str, message: str | dict) -> json.dumps:
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
    def message_payload(self, sender_user_id: str, receiver_user_id: str, text) -> json.dumps:
        """
        A sub-json payload definition to send an encrypted text
        """
        text_payload = {
            "recv_user_id": receiver_user_id,
            "text": text,
            "sender_user_id": sender_user_id
        }

        return self.payload("Encrypted", text_payload)

    @staticmethod
    def check_ACTIVEUSER(self, user_id: str):
        """
        Checks if the user is active or not.
        """
        for i in self.ACTIVEUSERS.keys():
            if self.ACTIVEUSERS[i][0] == user_id:
                return i
            else:
                continue
        else:
            return False

    def check_credentials(self, user_id: str, *password: str):
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

    def send_text(self, sender_id: str, receiver_id: str, text: bytes) -> bool:
        """
        Redirect the text to the receiver.
        :param sender_id:
        :param receiver_id:
        :param text:
        :return bool:
        """
        try:
            socket = self.check_ACTIVEUSER(receiver_id)
            if socket:
                command_payload = {'method': 'send_text', 'args': self.message_payload(self, sender_id, receiver_id, text)}
                self.ACTIVEUSERS[socket][1].command_queue.put(command_payload)
                self.insert_into_textcache(text, sender_id, receiver_id, True)
                return True
            else:
                self.insert_into_textcache(text, sender_id, receiver_id)
                return False

        except Exception as e:
            print(f"Error in caching.send_text: {e}")

    def
