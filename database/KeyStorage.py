from typing import Dict
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
                           identity_key: str,
                           identity_key_dh: str,
                           signed_pre_key: str,
                           signed_pre_key_signature: str,
                           one_time_pre_key: dict[str, str]) -> bool:
        """
        Calls the Storage manager to save the KeyBundle to the database.
        :param user_id:
        :param identity_key:
        :param identity_key_dh:
        :param signed_pre_key:
        :param signed_pre_key_signature:
        :param one_time_pre_key:
        :return: List
        """

        KeyBundlePayload = {
            "user_id": user_id,
            "identity_key": identity_key,
            "identity_key_dh": identity_key_dh,
            "signed_pre_key": signed_pre_key,
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