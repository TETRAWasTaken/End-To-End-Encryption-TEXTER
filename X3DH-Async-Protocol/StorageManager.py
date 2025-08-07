import json
import os
import DB_connect as DBC
import datetime
import psycopg2

"""
This class is meant for retrieval and manipulation of file storage
This class will later be updated to use a SQL based database managment system for better performance and security
"""

class StorageManager:
    def __init__(self, user_id : str, DB : DBC.DB_connect) -> None:
        self.user_id = user_id if user_id else None
        try:
            self.DB = DB
        except Exception as e:
            print(f"Error : {e} while initialising KeyStorage")

    def SaveKeyBundle(self, KeyBundle: dict, user_id : str) -> None:
        """
        This Function saves the KeyBundle to the database.
        :param KeyBundle:
        :param user_id:
        :return:
        """
        try:
            cur = self.DB.pool.getconn.cursor()
            # Inserting Identity Key
            cur.execute("Insert into identity_key (user_id, identity_key, time_stamp_creation) values (%s, %s, %s)",
                             (user_id, KeyBundle['identity_key'], datetime.datetime.now()))

            # Inserting Signed Pre-Key
            cur.execute("Insert into signed_pre_key (user_id, signed_pre_key, signature, time_stamp_creation) values (%s, %s, %s, %s)",
                             (user_id, KeyBundle['signed_pre_key'], KeyBundle['signature'], datetime.datetime.now()))

            # Inserting One-time Pre Key
            cur.executemany("Insert into one_time_pre_key (user_id, one_time_pre_key, time_stamp_creation) values (%s, %s, %s)",
                             (user_id, KeyBundle['one_time_pre_key'], datetime.datetime.now()))

        except Exception as e:
            print(f"Error : {e} while saving KeyBundle")
        finally:
            self.conn.commit()

    def LoadKeyBundle(self, user_id : str) -> dict:
        """
        This Function loads the KeyBundle from the database.
        :param user_id:
        :return: KeyBundle : dict
        """
        try:
            # Retrieving Identity Key
            self.cur.execute("Select identity_key from identity_key where user_id = %s",
                             (user_id,))
            identity_key = self.cur.fetchone()[0]

            # Retrieving Signed_Pre_Key and Signature
            self.cur.execute("Select signed_pre_key, signature from signed_key where user_id = %s",
                             (user_id,))
            signed_pre_key, signature = self.cur.fetchall()

            # Retrieving One_Time_Key
            self.cur.execute("Select key_id, one_time_pre_key from one_time_pre_key where user_id = %s and is_used = False order by time_stamp_creation ASC limit 1 for update skip locked",
                             (user_id,))
            one_time_pre_key = self.cur.fetchone()
            if one_time_pre_key:
                key_id, one_time_pre_key = one_time_pre_key
                self.cur.execute("Update one_time_pre_key set is_used = True where key_id = %s", (key_id,))
                self.conn.commit()
            else:
                one_time_pre_key = {}

            KeyBundle = {"identity_key":identity_key,
                         "signed_pre_key":signed_pre_key,
                         "signature":signature,
                         "one_time_pre_key":one_time_pre_key,
                         "user_id":user_id,
                         "one_time_key_id":key_id
                         }
            return KeyBundle

        except Exception as e:
            print(f"Error : {e} while loading KeyBundle")
            return {}

    def DeleteKeyBundle(self, user_id : str) -> None:
        try:
            self.cur.execute("Delete from identity_key where user_id = %s", (user_id,))
            self.cur.execute("Delete from signed_pre_key where user_id = %s", (user_id,))
            self.cur.execute("Delete from one_time_pre_key where user_id = %s", (user_id,))
            self.conn.commit()
        except Exception as e:
            print(f"Error : {e} while deleting KeyBundle")

        finally:
            self.conn.commit()
