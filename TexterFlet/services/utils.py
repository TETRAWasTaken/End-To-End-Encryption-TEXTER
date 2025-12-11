from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Constants
ROOT_KEY_LEN = 32
CHAIN_KEY_LEN = 32
MESSAGE_KEY_LEN = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
HKDF_HASH_ALGORITHM = hashes.SHA256()

class EncryptionUtil:
    def __init__(self):
        pass

    def generate_x25519_key_pair(self) -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
        private_key = x25519.X25519PrivateKey.generate()
        return private_key, private_key.public_key()

    def generate_ed25519_key_pair(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        private_key = ed25519.Ed25519PrivateKey.generate()
        return private_key, private_key.public_key()

    def derive_HKDF_key(self, key: bytes, salt: bytes, info: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=HKDF_HASH_ALGORITHM,
            length=CHAIN_KEY_LEN,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(key)

    def encrypt_aes_gcm(self, key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, nonce, encryptor.tag

    def decrypt_aes_gcm(self, key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: Optional[bytes] = None) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    def hkdf(self, input_key_material: bytes, salt: bytes, length: int = 32) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=b'handshake data',
            backend=default_backend()
        )
        return hkdf.derive(input_key_material)