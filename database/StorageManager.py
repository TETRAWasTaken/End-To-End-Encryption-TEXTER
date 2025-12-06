from __future__ import annotations
from database import DB_connect as DB
import datetime
from typing import Dict, List

class StorageManager:
    """
    Manages all database operations for the server.

    This class provides a high-level API for interacting with the PostgreSQL
    database. It encapsulates all SQL queries, ensuring that they are safe from
    injection attacks and that database interactions are consistent and
    reliable. It handles operations related to user accounts, key bundles,
    friendships, and other application data.
    """
    def __init__(self, DB: DB.DB_connect) -> None:
        """
        Initializes the StorageManager with a database connection object.

        Args:
            DB: An instance of the DB_connect class.
        """
        self.DB = DB

    def UserExists(self, user_id: str) -> bool:
        """
        Checks if a user exists in the database.

        Args:
            user_id: The unique identifier of the user.

        Returns:
            True if the user exists, False otherwise.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute("SELECT EXISTS (SELECT 1 FROM User_Info WHERE user_id = %s)", (user_id,))
            return bool(cur.fetchone()[0])
        except Exception as e:
            print(f"Error : {e} while checking User")
            return False
        finally:
            if cur: cur.close()
            if conn: self.DB.pool.putconn(conn)

    def GetUserPasswordHash(self, user_id: str) -> str | None:
        """
        Retrieves the password hash for a given user.

        Args:
            user_id: The user's unique identifier.

        Returns:
            The password hash string, or None if the user doesn't exist.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute("SELECT password_hash FROM User_Info WHERE user_id = %s", (user_id,))
            result = cur.fetchone()
            return result[0] if result else None
        except Exception as e:
            print(f"Error : {e} while getting user password hash")
            return None
        finally:
            if cur: cur.close()
            if conn: self.DB.pool.putconn(conn)

    def InsertUser(self, user_id: str, password_hash: str) -> bool:
        """
        Inserts a new user with their username and hashed password.

        Args:
            user_id: The new user's username.
            password_hash: The Argon2 hashed password.

        Returns:
            True if insertion is successful, False otherwise.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute("INSERT INTO User_Info (user_id, password_hash) VALUES (%s, %s)", (user_id, password_hash))
            conn.commit()
            return True
        except Exception as e:
            if conn: conn.rollback()
            print(f"Error : {e} while inserting new user")
            return False
        finally:
            if cur: cur.close()
            if conn: self.DB.pool.putconn(conn)

    def SaveKeyBundle(self, KeyBundle: dict, user_id: str) -> bool:
        """
        Saves a user's cryptographic key bundle to the database.

        Args:
            KeyBundle: A dictionary containing the user's key bundle.
            user_id: The user's unique identifier.

        Returns:
            True if the bundle was saved successfully, False otherwise.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            time_stamp_cr = datetime.datetime.now()
            cur.execute(
                """
                INSERT INTO identity_key (user_id, identity_key, identity_key_dh, time_stamp_creation) 
                VALUES (%s, %s, %s, %s) 
                ON CONFLICT (user_id) 
                DO UPDATE SET identity_key = EXCLUDED.identity_key, identity_key_dh = EXCLUDED.identity_key_dh, time_stamp_creation = EXCLUDED.time_stamp_creation
                """,
                (user_id, KeyBundle['identity_key'], KeyBundle['identity_key_dh'], time_stamp_cr)
            )
            cur.execute(
                "INSERT INTO signed_key (user_id, signed_pre_key, signature, time_stamp_creation) VALUES (%s, %s, %s, %s)",
                (user_id, KeyBundle['signed_pre_key'], KeyBundle['signature'], time_stamp_cr)
            )
            one_time_rows = [(user_id, k, v, time_stamp_cr, False) for k, v in KeyBundle['one_time_pre_keys'].items()]
            if one_time_rows:
                cur.executemany(
                    "INSERT INTO onetime_pre_key (user_id, key_id, one_time_key, time_stamp_creation, is_used) VALUES (%s, %s, %s, %s, %s)",
                    one_time_rows,
                )
            conn.commit()
            return True
        except Exception as e:
            if conn: conn.rollback()
            print(f"Error : {e} while saving KeyBundle")
            return False
        finally:
            if cur: cur.close()
            if conn: self.DB.pool.putconn(conn)

    def LoadKeyBundle(self, user_id: str) -> Dict:
        """
        Loads a user's key bundle from the database for an X3DH handshake.

        Args:
            user_id: The user's unique identifier.

        Returns:
            A dictionary containing the user's key bundle, or an empty
            dictionary if not found or an error occurs.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute("Select identity_key, identity_key_dh from identity_key where user_id = %s", (user_id,))
            identity_key_row = cur.fetchone()
            if not identity_key_row: return {}
            
            identity_key, identity_key_dh = identity_key_row
            cur.execute("SELECT signed_pre_key, signature FROM signed_key WHERE user_id = %s ORDER BY time_stamp_creation DESC LIMIT 1", (user_id,))
            row = cur.fetchone()
            if not row:
                conn.rollback()
                return {}
            signed_pre_key, signature = row

            cur.execute("SELECT key_id, one_time_key FROM onetime_pre_key WHERE user_id = %s AND is_used = FALSE ORDER BY time_stamp_creation FOR UPDATE SKIP LOCKED LIMIT 1", (user_id,))
            otk_row = cur.fetchone()
            one_time_pre_key, one_time_key_id = (otk_row[1], otk_row[0]) if otk_row else (None, None)
            if otk_row:
                cur.execute("UPDATE onetime_pre_key SET is_used = TRUE WHERE key_id = %s", (one_time_key_id,))
            
            conn.commit()
            return {
                "identity_key": identity_key,
                "identity_key_dh": identity_key_dh,
                "signed_pre_key": signed_pre_key,
                "signature": signature,
                "one_time_pre_key": one_time_pre_key, 
                "user_id": user_id,
                "one_time_key_id": one_time_key_id, 
            }
        except Exception as e:
            if conn: conn.rollback()
            print(f"Error : {e} while loading KeyBundle")
            return {}
        finally:
            if cur: cur.close()
            if conn: self.DB.pool.putconn(conn)

    def DeleteKeyBundle(self, user_id: str) -> None:
        """
        Deletes a user's key bundle from the database.

        Args:
            user_id: The user's unique identifier.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute("Delete from identity_key where user_id = %s", (user_id,))
            cur.execute("Delete from signed_key where user_id = %s", (user_id,))
            cur.execute("Delete from onetime_pre_key where user_id = %s", (user_id,))
            conn.commit()
        except Exception as e:
            if conn: conn.rollback()
            print(f"Error : {e} while deleting KeyBundle")
        finally:
            if cur: cur.close()
            if conn: self.DB.pool.putconn(conn)

    def CheckFriendsStatus(self, user_one_id: str, user_two_id: str) -> bool:
        """
        Checks if two users are friends.

        Args:
            user_one_id: The ID of the first user.
            user_two_id: The ID of the second user.

        Returns:
            True if the users are friends, False otherwise.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute("SELECT EXISTS (SELECT 1 FROM friends WHERE ((user_one_id = %s AND user_two_id = %s) OR (user_one_id = %s AND user_two_id = %s)) AND status = 'accepted')", (user_one_id, user_two_id, user_two_id, user_one_id))
            return bool(cur.fetchone()[0])
        except Exception as e:
            print(f"Error : {e} while checking friends status")
            return False
        finally:
            if cur: cur.close()
            if conn: self.DB.pool.putconn(conn)

    def CreateFriendRequest(self, from_user_id: str, to_user_id: str) -> bool:
        """
        Creates a friend request from one user to another.

        Args:
            from_user_id: The user sending the request.
            to_user_id: The user receiving the request.

        Returns:
            True if the request was created successfully, False otherwise.
        """
        conn = None
        cur = None
        try:
            if from_user_id == to_user_id: return False
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute("SELECT EXISTS (SELECT 1 FROM User_Info WHERE user_id = %s)", (to_user_id,))
            if not cur.fetchone()[0]: return False
            cur.execute("SELECT 1 FROM friends WHERE (user_one_id = %s AND user_two_id = %s) OR (user_one_id = %s AND user_two_id = %s)", (from_user_id, to_user_id, to_user_id, from_user_id))
            if cur.fetchone(): return False
            cur.execute("INSERT INTO friends (user_one_id, user_two_id, status) VALUES (%s, %s, 'pending')", (from_user_id, to_user_id))
            conn.commit()
            return True
        except Exception as e:
            if conn: conn.rollback()
            print(f"Error in CreateFriendRequest: {e}")
            return False
        finally:
            if cur: cur.close()
            if conn: self.DB.pool.putconn(conn)

    def GetPendingFriendRequests(self, user_id: str) -> List[str]:
        """
        Retrieves a list of users who have sent a friend request to the given user.

        Args:
            user_id: The user to check for pending requests.

        Returns:
            A list of user IDs who have sent a request.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute("SELECT user_one_id FROM friends WHERE user_two_id = %s AND status = 'pending'", (user_id,))
            return [row[0] for row in cur.fetchall()]
        except Exception as e:
            print(f"Error in GetPendingFriendRequests: {e}")
            return []
        finally:
            if cur: cur.close()
            if conn: self.DB.pool.putconn(conn)

    def AcceptFriendRequest(self, from_user_id: str, to_user_id: str) -> bool:
        """
        Accepts a friend request.

        Args:
            from_user_id: The user who sent the request.
            to_user_id: The user who is accepting the request.

        Returns:
            True if the request was accepted successfully, False otherwise.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute("UPDATE friends SET status = 'accepted' WHERE user_one_id = %s AND user_two_id = %s AND status = 'pending'", (from_user_id, to_user_id))
            conn.commit()
            return cur.rowcount > 0
        except Exception as e:
            if conn: conn.rollback()
            print(f"Error in AcceptFriendRequest: {e}")
            return False
        finally:
            if cur: cur.close()
            if conn: self.DB.pool.putconn(conn)