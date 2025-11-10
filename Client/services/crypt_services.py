import base64
from Client.services import x3dh, utils
from cryptography.hazmat.primitives.asymmetric import x25519
import os
import json
from typing import Dict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def bytes_to_b64str(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def b64str_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

class CryptServices:
    """
    Wraps all X3DH and encryption logic to handle the
    bytes <-> str serialisation for JSON
    """
    def __init__(self, username: str):
        self.username = username
        self.x3dh = x3dh.X3DH(username)
        self.utils = utils.EncryptionUtil()
        self.session_keys = {} # dict -> key: reciever_id, value: b"session_key"
        self._key_file = f"{username}.keystore.json"

    def _derive_file_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a 32-byte AES key from the user's password and add as salt
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode("utf-8"))

    def generate_and_save_key(self, password: str) -> str:
        """
        During Registration,
        Generates the keybundle and save the private key in the solid storage
        """
        public_key_bundle, private_key_bundle = self.x3dh.generate_key_bundle()
        #TODO: handle the private keys

    def serializabole_key_bundle(self) -> Dict:
        """
        Generates a key bundle and serializes all
        public keys bytes into base64 str
        """
        key_bundle = self.x3dh.generate_key_bundle()
        serialized_key_bundle = {
            "identity_key": bytes_to_b64str(key_bundle["identity_key"]),
            "signed_pre_key": bytes_to_b64str(key_bundle["signed_pre_key"]),
            "signed_pre_key_signature": bytes_to_b64str(key_bundle["signed_pre_key_signature"]),
            "one_time_pre_keys": {
                key_id: bytes_to_b64str(opk)
                for key_id, opk in key_bundle["one_time_pre_keys"].items()
            }
        }
        #TODO: complete and correct this function

