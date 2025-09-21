from __future__ import annotations
import threading
from typing import Any, Coroutine

import psycopg2
import websockets
import json
import asyncio

from X3DH import DB_connect

class caching:
    def __init__(self, DB: DB_connect.DB_connect):
        print("Initialising Caching system")
        self.DB = DB
        self.onlineClients = {}

    def payload(self, status: str, message: str) -> json.dumps:
        """
        Describes the general payload of each message sent
        :param status: The basic code of sent message, can be "error", "ok"
        :param message: The extra details that needs to be sent
        :return payload: A JSON object containing the status and message
        """

        payload = {
            "status": status,
            "message": message
        }
        return json.dumps(payload)

    def check_credentials(self, user_id: str, password: str):
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
        try:
            conn = self.DB.pool.getconn()
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM user_info WHERE user_id = %s AND password = %s",
                            (user_id, password))
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


