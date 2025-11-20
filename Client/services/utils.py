from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import threading

# Constants
ROOT_KEY_LEN = 32
CHAIN_KEY_LEN = 32
MESSAGE_KEY_LEN = 32
AES_GCM_NONCE_BYTES = 12  # 96 bits
AES_GCM_TAG_BYTES = 16  # 128 bits
HKDF_HASH_ALGORITHM = hashes.SHA256()

class CryptoCounters:
    """
    A thread-safe singleton for tracking cryptographic statistics.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(CryptoCounters, cls).__new__(cls)
                cls._instance.reset()
        return cls._instance

    def reset(self):
        self.x3dh_sessions_initiated_alice = 0
        self.x3dh_sessions_initiated_bob = 0
        self.messages_encrypted = 0
        self.messages_decrypted = 0
        self.decryption_failures_invalid_tag = 0
        self.skipped_messages_processed = 0
        self.old_messages_discarded = 0
        self.bundle_validation_failures = 0

    def increment(self, counter_name):
        with self._lock:
            if hasattr(self, counter_name):
                setattr(self, counter_name, getattr(self, counter_name) + 1)

    def __str__(self):
        return (
            "--- Crypto Statistics ---\n"
            f"X3DH Handshakes (Alice): {self.x3dh_sessions_initiated_alice}\n"
            f"X3DH Handshakes (Bob):   {self.x3dh_sessions_initiated_bob}\n"
            f"Messages Encrypted:      {self.messages_encrypted}\n"
            f"Messages Decrypted:      {self.messages_decrypted}\n"
            f"Skipped Msgs Processed:  {self.skipped_messages_processed}\n"
            f"Old Msgs Discarded:      {self.old_messages_discarded}\n"
            f"Bundle Failures:         {self.bundle_validation_failures}\n"
            f"DECRYPTION FAILURES:     {self.decryption_failures_invalid_tag}\n"
            "-------------------------"
        )

class EncryptionUtil():
    def __init__(self):
        self.counters = CryptoCounters()

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
                    length=CHAIN_KEY_LEN,
                    salt=salt,
                    info=info,
                    backend=default_backend()
                    )
        return hkdf.derive(key)

    def encrypt_aes_gcm(self, key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[
        bytes, bytes, bytes]:
        """
        Encrypts plaintext using AES-256-GCM.
        :param key: The key to use for encryption.
        :param plaintext: The plaintext to encrypt.
        :param associated_data: Additional data to authenticate.
        :return: A tuple containing ciphertext, nonce, and tag.
        """
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        self.counters.increment('messages_encrypted')
        return ciphertext, nonce, tag

    def decrypt_aes_gcm(self, key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes,
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
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        self.counters.increment('messages_decrypted')
        return plaintext
