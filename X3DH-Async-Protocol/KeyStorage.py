from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
import cryptography
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import StorageManager

"""
This is a Key storage protocol for the Server, this 
"""

class KeyStorage:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.identity_key : Optional[x25519.X25519PublicKey] = None
        self.signed_pre_key : Optional[x25519.X25519PublicKey] = None
        self.signed_pre_key_signature : Optional[bytes] = None
        self.one_time_pre_key : Dict[int, x25519.X25519PublicKey] = {}
        self.StorageManager = StorageManager.StorageManager

    def StoreUserKeyBundle(self, user_id: str,
                           identity_key: x25519.X25519PublicKey,
                           signed_pre_key: x25519.X25519PublicKey,
                           signed_pre_key_signature: bytes,
                           one_time_pre_key: dict[int, x25519.X25519PublicKey]) -> None:

        KeyBundlePayload = {
            user_id: user_id,
            identity_key: identity_key,
            signed_pre_key: signed_pre_key,
            signed_pre_key_signature: signed_pre_key_signature,
            one_time_pre_key: one_time_pre_key
        }

        self.StorageManager.SaveKeyBundle(KeyBundlePayload, self.user_id)

    def LoadUserKeyBundle(self) -> dict:
        try :
            KeyBundle = self.StorageManager.LoadKeyBundle(self.user_id)
            if KeyBundle:
                return KeyBundle
            else:
                return {}
        except Exception as e:
            print(f"Error : {e} while loading KeyBundle")
            return {}

    def Check_User