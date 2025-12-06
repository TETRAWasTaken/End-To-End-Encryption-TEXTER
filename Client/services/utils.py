from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
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
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
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
        """Resets all counters to zero."""
        self.x3dh_sessions_initiated_alice = 0
        self.x3dh_sessions_initiated_bob = 0
        self.messages_encrypted = 0
        self.messages_decrypted = 0
        self.decryption_failures_invalid_tag = 0
        self.skipped_messages_processed = 0
        self.old_messages_discarded = 0
        self.bundle_validation_failures = 0

    def increment(self, counter_name: str):
        """
        Increments a specific counter by one.

        Args:
            counter_name: The name of the counter attribute to increment.
        """
        with self._lock:
            if hasattr(self, counter_name):
                setattr(self, counter_name, getattr(self, counter_name) + 1)

    def __str__(self):
        """Returns a string representation of the current statistics."""
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

class EncryptionUtil:
    """
    A utility class providing common cryptographic functions.

    This class wraps fundamental cryptographic operations such as key
    generation, key derivation, and authenticated encryption, making them
    easily accessible throughout the application.
    """
    def __init__(self):
        """Initializes the EncryptionUtil and its associated CryptoCounters."""
        self.counters = CryptoCounters()

    def generate_x25519_key_pair(self) -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
        """
        Generates an X25519 key pair for Diffie-Hellman key exchange.

        Returns:
            A tuple containing the private and public keys.
        """
        private_key = x25519.X25519PrivateKey.generate()
        return private_key, private_key.public_key()

    def generate_ed25519_key_pair(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """
        Generates an Ed25519 key pair for digital signatures.

        Returns:
            A tuple containing the private and public keys.
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        return private_key, private_key.public_key()

    def derive_HKDF_key(self, key: bytes, salt: bytes, info: bytes) -> bytes:
        """
        Derives a new key using the HKDF standard.

        Args:
            key: The input key material.
            salt: A non-secret salt value.
            info: Optional context and application specific information.

        Returns:
            The derived key of length CHAIN_KEY_LEN.
        """
        hkdf = HKDF(
            algorithm=HKDF_HASH_ALGORITHM,
            length=CHAIN_KEY_LEN,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(key)

    def encrypt_aes_gcm(self, key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypts plaintext using AES-256-GCM.

        Args:
            key: The 32-byte encryption key.
            plaintext: The data to encrypt.
            associated_data: Optional data to authenticate but not encrypt.

        Returns:
            A tuple containing the ciphertext, nonce, and authentication tag.
        """
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        self.counters.increment('messages_encrypted')
        return ciphertext, nonce, encryptor.tag

    def decrypt_aes_gcm(self, key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypts ciphertext using AES-256-GCM.

        Args:
            key: The 32-byte decryption key.
            ciphertext: The data to decrypt.
            nonce: The nonce used during encryption.
            tag: The authentication tag to verify.
            associated_data: Optional authenticated data to verify.

        Returns:
            The decrypted plaintext.

        Raises:
            InvalidTag: If the authentication check fails.
        """
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        self.counters.increment('messages_decrypted')
        return plaintext

    def hkdf(self, input_key_material: bytes, salt: bytes, length: int = 32) -> bytes:
        """
        Performs a single HKDF extraction and expansion.

        Args:
            input_key_material: The input keying material.
            salt: The salt value.
            length: The desired output length in bytes.

        Returns:
            The derived key.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=b'handshake data',
            backend=default_backend()
        )
        return hkdf.derive(input_key_material)