from __future__ import annotations

from database import DB_connect as DB
import datetime
from typing import Dict, List

"""
This class is meant for retrieval and manipulation of file storage
This class will later be updated to use a SQL based database managment system for better performance and security
"""

class StorageManager:
    """
    This class is meant for retrieval and manipulation of file storage
    This class acts as an API for the database querying and prevents SQL vulnerabilities
    by seperating all the queryies in this class and keeping them injection safe
    """
    def __init__(self, DB : DB.DB_connect) -> None:
        try:
            self.DB = DB
        except Exception as e:
            print(f"Error : {e} while initialising KeyStorage")

    def UserExists(self, user_id : str) -> bool:
        """
        Query the database to check if the user exists
        :param user_id:
        :return:
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute(
                "SELECT EXISTS (SELECT 1 FROM User_Info WHERE user_id = %s)",
                (user_id,),
            )
            exists = cur.fetchone()[0]
            return bool(exists)
        except Exception as e:
            print(f"Error : {e} while checking User")
            return False
        finally:
            try:
                if cur is not None:
                    cur.close()
            finally:
                if conn is not None:
                    self.DB.pool.putconn(conn)

    def GetUserPasswordHash(self, user_id: str) -> str | None:
        """
        Retrieves the password hash for a given user.
        :param user_id: The user's username.
        :return: The password hash string, or None if the user doesn't exist.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute(
                "SELECT password_hash FROM User_Info WHERE user_id = %s",
                (user_id,),
            )
            result = cur.fetchone()
            return result[0] if result else None
        except Exception as e:
            print(f"Error : {e} while getting user password hash")
            return None
        finally:
            try:
                if cur is not None:
                    cur.close()
            finally:
                if conn is not None:
                    self.DB.pool.putconn(conn)

    def InsertUser(self, user_id: str, password_hash: str) -> bool:
        """
        Inserts a new user with their username and hashed password.
        :param user_id: The new user's username.
        :param password_hash: The Argon2 hashed password.
        :return: True if insertion is successful, False otherwise.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            # Assuming your user table is named User_Info and has these columns
            cur.execute(
                "INSERT INTO User_Info (user_id, password_hash) VALUES (%s, %s)",
                (user_id, password_hash),
            )
            conn.commit()
            return True
        except Exception as e:
            if conn is not None:
                conn.rollback()
            print(f"Error : {e} while inserting new user")
            return False
        finally:
            try:
                if cur is not None:
                    cur.close()
            finally:
                if conn is not None:
                    self.DB.pool.putconn(conn)


    def SaveKeyBundle(self, KeyBundle: dict, user_id : str) -> bool:
        """
        This Function saves the KeyBundle to the database.
        :param KeyBundle:
        :param user_id:
        :return:
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()

            time_stamp_cr = datetime.datetime.now()
            # Inserting Identity Keys (Both Signing and DH)
            # UPDATED QUERY: Added identity_key_dh
            cur.execute(
                """
                INSERT INTO identity_key (user_id, identity_key, identity_key_dh, time_stamp_creation) 
                VALUES (%s, %s, %s, %s) 
                ON CONFLICT (user_id) 
                DO UPDATE SET 
                    identity_key = EXCLUDED.identity_key, 
                    identity_key_dh = EXCLUDED.identity_key_dh,
                    time_stamp_creation = EXCLUDED.time_stamp_creation
                """,
                (user_id, KeyBundle['identity_key'], KeyBundle['identity_key_dh'], time_stamp_cr)
            )

            # Inserting Signed Pre-Key
            cur.execute(
                "INSERT INTO signed_key (user_id, signed_pre_key, signature, time_stamp_creation) VALUES (%s, %s, %s, %s)",
                (user_id, KeyBundle['signed_pre_key'], KeyBundle['signature'], time_stamp_cr)
            )

            # Inserting One-time Pre Keys (executemany expects an iterable of tuples)
            one_time_rows = [
                (user_id, k, v, time_stamp_cr, False) # Add 'is_used = FALSE'
                for k, v in KeyBundle['one_time_pre_keys'].items()
            ]
            if one_time_rows:
                cur.executemany(
                    "INSERT INTO onetime_pre_key (user_id, key_id, one_time_key, time_stamp_creation, is_used) VALUES (%s, %s, %s, %s, %s)",
                    one_time_rows,
                )

            conn.commit()
            return True
        except Exception as e:
            if conn is not None:
                conn.rollback()
            print(f"Error : {e} while saving KeyBundle")
            return False
        finally:
            try:
                if cur is not None:
                    cur.close()
            finally:
                if conn is not None:
                    self.DB.pool.putconn(conn)

    def LoadKeyBundle(self, user_id: str) -> Dict:
        """
        This Function loads the KeyBundle from the database.
        :param user_id:
        :return: KeyBundle : dict
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            # Retrieving Identity Keys
            # UPDATED QUERY: Added identity_key_dh
            cur.execute("Select identity_key, identity_key_dh from identity_key where user_id = %s",
                        (user_id,))
            identity_key_row = cur.fetchone()
            if not identity_key_row:
                return {} # Return empty if no identity key found
            
            identity_key = identity_key_row[0]
            identity_key_dh = identity_key_row[1] # Extract the DH key

            # Retrieving Signed_Pre_Key and Signature
            cur.execute(
                "SELECT signed_pre_key, signature FROM signed_key WHERE user_id = %s ORDER BY time_stamp_creation DESC LIMIT 1",
                (user_id,),
            )
            row = cur.fetchone()
            if not row:
                conn.rollback()
                return {}
            signed_pre_key, signature = row

            # Retrieve one available One-Time Key with lock, and mark it used
            cur.execute(
                """
                SELECT key_id, one_time_key
                FROM onetime_pre_key
                WHERE user_id = %s
                  AND is_used = FALSE
                ORDER BY time_stamp_creation
                    FOR UPDATE SKIP LOCKED
                LIMIT 1
                """,
                (user_id,),
            )
            otk_row = cur.fetchone()
            one_time_pre_key = None
            one_time_key_id = None
            if otk_row:
                one_time_key_id, one_time_pre_key = otk_row
                cur.execute(
                    "UPDATE onetime_pre_key SET is_used = TRUE WHERE key_id = %s",
                    (one_time_key_id,),
                )

            # Commit the transaction so the is_used flag is persisted atomically with the selection
            conn.commit()

            return {
                "identity_key": identity_key,
                "identity_key_dh": identity_key_dh, # Return it in the bundle
                "signed_pre_key": signed_pre_key,
                "signature": signature,
                "one_time_pre_key": one_time_pre_key, 
                "user_id": user_id,
                "one_time_key_id": one_time_key_id, 
            }
        except Exception as e:
            if conn is not None:
                conn.rollback()
            print(f"Error : {e} while loading KeyBundle")
            return {}
        finally:
            try:
                if cur is not None:
                    cur.close()
            finally:
                if conn is not None:
                    self.DB.pool.putconn(conn)

    def DeleteKeyBundle(self, user_id : str) -> None:
        """
        Deletes the KeyBundle from the database.
        :param user_id:
        :return:
        """
        try:
            conn = self.DB.pool.getconn
            cur = conn.cursor()
            cur.execute("Delete from identity_key where user_id = %s", (user_id,))
            cur.execute("Delete from signed_key where user_id = %s", (user_id,))
            cur.execute("Delete from onetime_pre_key where user_id = %s", (user_id,))
            conn.commit()
            self.DB.pool.putconn(conn)
        except Exception as e:
            print(f"Error : {e} while deleting KeyBundle")

    def CheckFriendsStatus(self, user_one_id : str, user_two_id : str) -> bool:
        """
        Check if two users are friends or not
        :param user_one_id:
        :param user_two_id:
        :return bool:
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute(
                "SELECT EXISTS (SELECT 1 FROM friends WHERE (user_one_id = %s AND user_two_id = %s) OR (user_one_id = %s AND user_two_id = %s) AND status = %s)"
                , (user_one_id, user_two_id, user_two_id, user_one_id, "accepted"))
            exists = cur.fetchone()[0]
            return bool(exists)

        except Exception as e:
            print(f"Error : {e} while checking friends status")
            return False
        finally:
            try:
                if cur is not None:
                    cur.close()
            finally:
                if conn is not None:
                    self.DB.pool.putconn(conn)

    def CreateFriendRequest(self, from_user_id: str, to_user_id: str) -> bool:
        """
        Creates a friend request from one user to another.
        :param from_user_id: The user sending the request.
        :param to_user_id: The user receiving the request.
        :return: True if the request was created successfully, False otherwise.
        """
        conn = None
        cur = None
        try:
            # 1. Don't allow self-requests
            if from_user_id == to_user_id:
                return False

            conn = self.DB.pool.getconn()
            cur = conn.cursor()

            # 2. Check if target user exists
            cur.execute("SELECT EXISTS (SELECT 1 FROM User_Info WHERE user_id = %s)", (to_user_id,))
            if not cur.fetchone()[0]:
                return False # Target user doesn't exist

            # 3. Check if they are already friends or a request is pending
            cur.execute(
                """
                SELECT 1 FROM friends 
                WHERE (user_one_id = %s AND user_two_id = %s) OR (user_one_id = %s AND user_two_id = %s)
                """,
                (from_user_id, to_user_id, to_user_id, from_user_id)
            )
            if cur.fetchone():
                return False # A relationship (friend or pending) already exists

            # 4. Insert the new friend request
            cur.execute(
                "INSERT INTO friends (user_one_id, user_two_id, status) VALUES (%s, %s, %s)",
                (from_user_id, to_user_id, "pending"),
            )
            conn.commit()
            return True

        except Exception as e:
            if conn:
                conn.rollback()
            print(f"Error in CreateFriendRequest: {e}")
            return False
        finally:
            if cur:
                cur.close()
            if conn:
                self.DB.pool.putconn(conn)

    def GetPendingFriendRequests(self, user_id: str) -> List[str]:
        """
        Retrieves a list of users who have sent a friend request to the given user.
        :param user_id: The user to check for pending requests.
        :return: A list of user_ids who have sent a request.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute(
                "SELECT user_one_id FROM friends WHERE user_two_id = %s AND status = %s",
                (user_id, "pending"),
            )
            requests = [row[0] for row in cur.fetchall()]
            return requests
        except Exception as e:
            print(f"Error in GetPendingFriendRequests: {e}")
            return []
        finally:
            if cur:
                cur.close()
            if conn:
                self.DB.pool.putconn(conn)

    def AcceptFriendRequest(self, from_user_id: str, to_user_id: str) -> bool:
        """
        Accepts a friend request.
        :param from_user_id: The user who sent the request.
        :param to_user_id: The user who is accepting the request.
        :return: True if the request was accepted successfully, False otherwise.
        """
        conn = None
        cur = None
        try:
            conn = self.DB.pool.getconn()
            cur = conn.cursor()
            cur.execute(
                "UPDATE friends SET status = %s WHERE user_one_id = %s AND user_two_id = %s AND status = %s",
                ("accepted", from_user_id, to_user_id, "pending"),
            )
            conn.commit()
            return cur.rowcount > 0
        except Exception as e:
            if conn:
                conn.rollback()
            print(f"Error in AcceptFriendRequest: {e}")
            return False
        finally:
            if cur:
                cur.close()
            if conn:
                self.DB.pool.putconn(conn)
