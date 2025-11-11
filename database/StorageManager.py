from database import DB_connect as DB
import datetime
from typing import Dict

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

    def check_user(self, user_id : str) -> bool:
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
            # Inserting Identity Key
            cur.execute(
                "INSERT INTO identity_key (user_id, identity_key, time_stamp_creation) VALUES (%s, %s, %s)",
                (user_id, KeyBundle['identity_key'], time_stamp_cr),
            )

            # Inserting Signed Pre-Key
            cur.execute(
                "INSERT INTO signed_key (user_id, signed_pre_key, signature, time_stamp_creation) VALUES (%s, %s, %s, %s)",
                (user_id, KeyBundle['signed_pre_key'], KeyBundle['signature'], time_stamp_cr),
            )

            # Inserting One-time Pre Keys (executemany expects an iterable of tuples)
            one_time_rows = [
                (user_id, k, v, time_stamp_cr)
                for k, v in KeyBundle['one_time_pre_key'].items() 
            ]
            if one_time_rows:
                cur.executemany(
                    "INSERT INTO onetime_pre_key (user_id, key_id, one_time_key, time_stamp_creation) VALUES (%s, %s, %s, %s)",
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
            # Retrieving Identity Key
            cur.execute("Select identity_key from identity_key where user_id = %s",
                        (user_id,))
            identity_key = cur.fetchone()[0]

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
                "signed_pre_key": signed_pre_key,
                "signed_pre_key_signature": signature,
                "one_time_pre_key": one_time_pre_key, # Will be None if not found
                "user_id": user_id,
                "one_time_key_id": one_time_key_id, # Will be None if not found
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
