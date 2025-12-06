from typing import Dict
from database import StorageManager

class KeyStorage:
    """
    Provides a high-level interface for storing and retrieving user key bundles.

    This class acts as a wrapper around the StorageManager, simplifying the
    process of saving, loading, and deleting the cryptographic key bundles
    required for the X3DH protocol. It abstracts the underlying database
    operations, providing a clear and concise API for key management.
    """
    def __init__(self, storagemanager: StorageManager.StorageManager):
        """
        Initializes the KeyStorage with a StorageManager instance.

        Args:
            storagemanager: An instance of the StorageManager for database access.
        """
        self.StorageManager = storagemanager

    def StoreUserKeyBundle(self, user_id: str, identity_key: str, identity_key_dh: str, signed_pre_key: str, signed_pre_key_signature: str, one_time_pre_key: dict[str, str]) -> bool:
        """
        Stores a user's key bundle in the database.

        Args:
            user_id: The user's unique identifier.
            identity_key: The user's public identity key (signing).
            identity_key_dh: The user's public identity key (DH).
            signed_pre_key: The user's signed pre-key.
            signed_pre_key_signature: The signature of the signed pre-key.
            one_time_pre_key: A dictionary of one-time pre-keys.

        Returns:
            True if the bundle was stored successfully, False otherwise.
        """
        KeyBundlePayload = {
            "user_id": user_id,
            "identity_key": identity_key,
            "identity_key_dh": identity_key_dh,
            "signed_pre_key": signed_pre_key,
            "signature": signed_pre_key_signature,
            "one_time_pre_key": one_time_pre_key
        }
        return self.StorageManager.SaveKeyBundle(KeyBundlePayload, user_id)

    def LoadUserKeyBundle(self, user_id: str) -> Dict:
        """
        Loads a user's key bundle from the database.

        Args:
            user_id: The user's unique identifier.

        Returns:
            A dictionary containing the user's key bundle, or an empty
            dictionary if not found or an error occurs.
        """
        try:
            KeyBundle = self.StorageManager.LoadKeyBundle(user_id)
            return KeyBundle if KeyBundle else {}
        except Exception as e:
            print(f"Error : {e} while loading KeyBundle")
            return {}

    def DeleteUserKeyBundle(self, user_id: str) -> bool:
        """
        Deletes a user's key bundle from the database.

        Args:
            user_id: The user's unique identifier.

        Returns:
            True if the bundle was deleted successfully, False otherwise.
        """
        try:
            self.StorageManager.DeleteKeyBundle(user_id)
            return True
        except Exception as e:
            print(f"Error : {e} while deleting KeyBundle")
            return False