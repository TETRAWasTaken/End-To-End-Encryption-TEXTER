import queue
import threading
from typing import Dict, List, Optional, Tuple, Union
from cryptography.hazmat.primitives.asymmetric import x25519

from database import StorageManager

"""
This is a Key storage protocol for the Server, this maintains the reliability 
in storing the keys accurately
"""

class KeyStorage:
    """
    This class is meant for retrieval and manipulation of file storage
    """
    def __init__(self, storagemanager: StorageManager.StorageManager):
        self.StorageManager= storagemanager

    def StoreUserKeyBundle(self, user_id: str,
                           identity_key: x25519.X25519PublicKey,
                           signed_pre_key: x25519.X25519PublicKey,
                           signing_key: bytes,
                           signed_pre_key_signature: bytes,
                           one_time_pre_key: dict[str, x25519.X25519PublicKey]) -> bool:
        """
        Calls the Storage manager to save the KeyBundle to the database.
        :param user_id:
        :param identity_key:
        :param signed_pre_key:
        :param signed_pre_key_signature:
        :param one_time_pre_key:
        :return: List
        """

        KeyBundlePayload = {
            "user_id": user_id,
            "identity_key": identity_key,
            "signed_pre_key": signed_pre_key,
            "signing_key": signing_key,
            "signature": signed_pre_key_signature,
            "one_time_pre_key": one_time_pre_key
        }

        if self.StorageManager.SaveKeyBundle(KeyBundlePayload, user_id):
            return True
        else:
            return False

    def LoadUserKeyBundle(self, user_id: str) -> Dict:
        """
        call the Storage manager to load the KeyBundle from the database.
        :return: Dict
        """
        try :
            KeyBundle = self.StorageManager.LoadKeyBundle(user_id)
            if KeyBundle:
                return KeyBundle
            else:
                return {}
        except Exception as e:
            print(f"Error : {e} while loading KeyBundle")
            return {}

    def _Check_User(self, user_id: str) -> bool:
        """
        Call the Storage manager to check if the user exists.
        :return: Bool
        """
        try:
            return self.StorageManager.check_user(user_id)
        except Exception as e:
            print(f"Error : {e} while checking User")
            return False

    def DeleteUserKeyBundle(self, user_id: str) -> bool:
        """
        Call the Storage manager to delete the KeyBundle from the database.
        :return: Bool
        """
        try:
            self.StorageManager.DeleteKeyBundle(user_id)
            return True
        except Exception as e:
            print(f"Error : {e} while deleting KeyBundle")
            return False