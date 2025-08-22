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

# Constants
ROOT_KEY_LEN = 32
CHAIN_KEY_LEN = 32
MESSAGE_KEY_LEN = 32
AES_GCM_NONCE_LEN = 96
AES_GCM_TAG_LEN = 128
HKDF_HASH_ALGORITHM = hashes.SHA256()


class EncryptionUtil():
    def __init__(self):
        pass
    def generate_x25519_key_pair(self):
        """
        Generates a private and public key pair for use in the X25519 algorithm.
        :return: A tuple containing the private key and public key.
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_ed25519_key_pair(self):
        """
        Generates a private and public key pair for use in the Ed25519 algorithm.
        :return: A tuple containing the private key and public key.
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_HKDF_key(self, key, salt, info):
        """
        Derives a key using HKDF.
        :param key: The key to derive from.
        :param salt: The salt to use.
        :param info: The info to use.
        :return: The derived key.
        """
        hkdf = HKDF(algorithm=HKDF_HASH_ALGORITHM,
                    length=CHAIN_KEY_LENGTH,
                    salt=salt,
                    info=info,
                    backend=default_backend()
                    )
        return hkdf.derive(key)

    def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[
        bytes, bytes, bytes]:
        """
        Encrypts plaintext using AES-256-GCM.
        :param key: The key to use for encryption.
        :param plaintext: The plaintext to encrypt.
        :param associated_data: Additional data to authenticate.
        :return: A tuple containing ciphertext, nonce, and tag.
        """
        nonce = os.urandom(AES_GCM_NONCE_LEN)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        return ciphertext, nonce, tag

    def decrypt_aes_gcm(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes,
                        associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypts ciphertext using AES-256-GCM.
        Raises InvalidTag exception on authentication failure.
        :param key: The key to use for decryption.
        :param ciphertext: The ciphertext to decrypt.
        :param nonce: The nonce used for encryption.
        :param tag: The tag used for authentication.
        :param associated_data: Additional data to authenticate.
        :return: The decrypted plaintext.
        """
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        return decryptor.update(ciphertext) + decryptor.finalize()


