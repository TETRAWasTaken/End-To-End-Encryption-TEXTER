from __future__ import annotations
import os
import json
from cryptography.exceptions import InvalidSignature, InvalidTag
from Client.services import x3dh, utils
from Client.services.double_ratchet import DoubleRatchetSession, bytes_to_b64str, b64str_to_bytes
from Client.services.database_service import DatabaseService
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from typing import Dict
from PySide6.QtCore import QStandardPaths


class CryptServices:
    """
    Manages all cryptographic operations for the client.

    This class is a high-level wrapper that orchestrates the X3DH key agreement
    protocol, the Double Ratchet algorithm for session management, and the
    secure storage of cryptographic keys and state. It interacts with the
    DatabaseService to persist user and session data.
    """

    def __init__(self, username: str):
        """
        Initializes the CryptServices for a given user.

        Args:
            username: The username of the local user.
        """
        self.username = username
        self.x3dh = x3dh.X3DH(username)
        self.utils = utils.EncryptionUtil()
        self.counters = utils.CryptoCounters()

        data_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation)
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)

        db_path = os.path.join(data_dir, f"{self.username}.db")
        self.db = DatabaseService(db_path)

        self._file_key: bytes | None = None
        self.partner_bundles: Dict[str, dict] = {}
        self.private_opks: Dict[int, x25519.X25519PrivateKey] = {}
        self.sessions: Dict[str, DoubleRatchetSession] = {}

    def _derive_file_key(self, password: str, salt: bytes) -> bytes:
        """
        Derives a key from a password and salt using PBKDF2.

        Args:
            password: The user's password.
            salt: A random salt.

        Returns:
            A 32-byte key for encrypting local storage.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000,
            backend=default_backend()
        )
        return kdf.derive(password.encode("utf-8"))

    def _X3DH_KDF(self, km: bytes) -> bytes:
        """
        Performs the Key Derivation Function (KDF) for the X3DH protocol.

        Args:
            km: The key material combined from the Diffie-Hellman exchanges.

        Returns:
            A 32-byte shared secret key.
        """
        F = b'\xFF' * 32
        salt = b'\x00' * 32
        ikm = F + km
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"X3DH",
            backend=default_backend()
        )
        return hkdf.derive(ikm)

    def generate_and_save_key(self, password: str) -> Dict | None:
        """
        Generates and saves a new set of cryptographic keys for registration.

        Args:
            password: The user's chosen password for the new account.

        Returns:
            A serializable public key bundle for the server, or None if a
            database for the user already exists.
        """
        if os.path.exists(self.db._db_path):
            print(f"Registration aborted: Database for user '{self.username}' already exists.")
            return None

        public_bundle_obj = self.x3dh.generate_key_bundle()
        salt = os.urandom(16)
        self._file_key = self._derive_file_key(password, salt)
        self.db.connect(self._file_key)
        self.db.create_tables()
        self.db.save_salt(salt)
        private_keys = self.x3dh.get_private_keys_for_saving()
        self.db.save_key("identity_key", private_keys["identity_key"])
        self.db.save_key("identity_key_dh", private_keys["identity_key_dh"])
        self.db.save_key("signed_pre_key", private_keys["signed_pre_key"])
        self.private_opks = self.x3dh.one_time_pre_keys_private
        self.db.save_opks(self.private_opks)
        self.db.close()
        return self.serializable_key_bundle(public_bundle_obj)

    def load_keys_from_disk(self, password: str) -> bool:
        """
        Loads the user's cryptographic state from the local database for login.

        Args:
            password: The user's password.

        Returns:
            True if the keys and sessions were loaded successfully, False
            otherwise (e.g., bad password or corrupted database).
        """
        try:
            self.db.connect(b'')
            salt = self.db.get_salt()
            if not salt:
                print("Login failed: could not retrieve salt from database.")
                self.db.close()
                return False

            self._file_key = self._derive_file_key(password, salt)
            if self.db.get_key("identity_key") is None:
                 raise ConnectionError("Simulated bad password or corrupted DB.")

            self.x3dh.load_private_keys(
                ik_priv_bytes=self.db.get_key("identity_key"),
                spk_priv_bytes=self.db.get_key("signed_pre_key"),
                ik_dh_priv_bytes=self.db.get_key("identity_key_dh")
            )
            self.private_opks = self.db.get_all_opks()
            self.sessions = self.db.get_all_sessions()
            return True
        except Exception as e:
            print(f"Database loading failed (bad password or corrupted file?): {e}")
            self._file_key = None
            if self.db.is_connected():
                self.db.close()
            return False

    def save_contacts_to_disk(self):
        """Saves the current list of session partners as contacts."""
        if self.db.is_connected():
            self.db.save_contacts(list(self.sessions.keys()))

    def load_contacts_from_disk(self) -> list:
        """
        Loads the contact list from the local database.

        Returns:
            A list of contact usernames.
        """
        return self.db.get_all_contacts() if self.db.is_connected() else []

    def serializable_key_bundle(self, bundle: dict) -> Dict:
        """
        Converts a public key bundle object into a JSON-serializable dictionary.

        Args:
            bundle: The public key bundle object.

        Returns:
            A dictionary with public keys encoded as base64 strings.
        """
        return {
            "identity_key": bytes_to_b64str(bundle["identity_key"].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "identity_key_dh": bytes_to_b64str(bundle["identity_key_dh"].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "signed_pre_key": bytes_to_b64str(bundle["signed_pre_key"].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "signature": bytes_to_b64str(bundle["signed_pre_key_signature"]),
            "one_time_pre_keys": {
                str(key_id): bytes_to_b64str(opk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
                for key_id, opk in bundle["one_time_pre_keys"].items()
            }
        }

    def store_partner_bundle(self, partner_username: str, bundle_json: dict):
        """
        Deserializes, verifies, and stores a partner's public key bundle.

        Args:
            partner_username: The username of the partner.
            bundle_json: The JSON dictionary containing the partner's bundle.
        """
        try:
            ik_str, ik_dh_str, spk_str, sig_str = (bundle_json.get(k) for k in ["identity_key", "identity_key_dh", "signed_pre_key", "signature"])
            if not all([ik_str, spk_str, sig_str, ik_dh_str]):
                self.counters.increment('bundle_validation_failures')
                raise ValueError("Received an incomplete key bundle.")

            ik_bytes, spk_bytes, signature_bytes = b64str_to_bytes(ik_str), b64str_to_bytes(spk_str), b64str_to_bytes(sig_str)
            opk_bytes = b64str_to_bytes(bundle_json.get("one_time_pre_key")) if bundle_json.get("one_time_pre_key") else None

            identity_key = ed25519.Ed25519PublicKey.from_public_bytes(ik_bytes)
            identity_key_dh = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(ik_dh_str))
            signed_pre_key = x25519.X25519PublicKey.from_public_bytes(spk_bytes)

            identity_key.verify(signature_bytes, spk_bytes)

            self.partner_bundles[partner_username] = {
                "identity_key": identity_key,
                "identity_key_dh": identity_key_dh,
                "signed_pre_key": signed_pre_key,
                "one_time_pre_key": x25519.X25519PublicKey.from_public_bytes(opk_bytes) if opk_bytes else None,
                "one_time_key_id": bundle_json.get("one_time_key_id")
            }
        except InvalidSignature:
            self.counters.increment('bundle_validation_failures')
            print(f"CRITICAL: Invalid signature on pre-key for {partner_username}. Bundle rejected.")
        except Exception as e:
            print(f"Error storing or verifying partner bundle for {partner_username}: {e}")

    def _initiate_session_alice(self, partner_username: str) -> tuple[dict, bytes]:
        """
        Initiates a secure session as 'Alice' (the initiator).

        Args:
            partner_username: The username of the session partner.

        Returns:
            A tuple containing the X3DH header for the initial message and the
            derived shared secret key.
        """
        if partner_username not in self.partner_bundles:
            raise Exception(f"No bundle for {partner_username}")

        bundle = self.partner_bundles[partner_username]
        p_ik_dh, p_spk_pub, p_opk_pub, opk_id = bundle['identity_key_dh'], bundle['signed_pre_key'], bundle.get("one_time_pre_key"), bundle.get("one_time_key_id")

        ek_priv, ek_pub = self.utils.generate_x25519_key_pair()
        ik_priv = self.x3dh.identity_key_dh_private

        DH1 = ik_priv.exchange(p_spk_pub)
        DH2 = ek_priv.exchange(p_ik_dh)
        DH3 = ek_priv.exchange(p_spk_pub)
        km = DH1 + DH2 + DH3 + (ek_priv.exchange(p_opk_pub) if p_opk_pub else b"")

        SK = self._X3DH_KDF(km)
        dr = DoubleRatchetSession(SK)
        dr.DHRatchet_for_alice_initial(p_spk_pub)
        self.sessions[partner_username] = dr
        self.db.save_session(partner_username, dr)
        self.counters.increment('x3dh_sessions_initiated_alice')

        x3dh_header = {
            "ik_a": bytes_to_b64str(ik_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "ek_a": bytes_to_b64str(ek_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "opk_id": opk_id
        }
        return x3dh_header, SK

    def _initiate_session_bob(self, partner_username: str, x3dh_header: dict, dr_header: dict) -> tuple[DoubleRatchetSession, bytes]:
        """
        Initiates a secure session as 'Bob' (the responder).

        Args:
            partner_username: The username of the session partner.
            x3dh_header: The X3DH header from the initial message.
            dr_header: The Double Ratchet header from the initial message.

        Returns:
            A tuple containing the newly created DoubleRatchetSession and the
            derived shared secret key.
        """
        p_ik_str, p_ek_str, opk_id = x3dh_header.get('ik_a'), x3dh_header.get('ek_a'), x3dh_header.get('opk_id')
        if not p_ik_str or not p_ek_str:
            raise ValueError("Received incomplete X3DH header from partner.")

        p_ik_pub = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(p_ik_str))
        p_ek_pub = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(p_ek_str))

        ik_priv, spk_priv = self.x3dh.identity_key_dh_private, self.x3dh.signed_pre_key_private
        opk_priv = self.db.pop_opk(int(opk_id)) if opk_id is not None else None
        if opk_id is not None and not opk_priv:
            print(f"Warning: Alice used OPK {opk_id}, but we don't have it.")

        DH1 = spk_priv.exchange(p_ik_pub)
        DH2 = ik_priv.exchange(p_ek_pub)
        DH3 = spk_priv.exchange(p_ek_pub)
        km = DH1 + DH2 + DH3 + (opk_priv.exchange(p_ek_pub) if opk_priv else b"")

        SK = self._X3DH_KDF(km)
        dr = DoubleRatchetSession(SK)
        
        alice_ratchet_pub_str = dr_header.get("dh_pub")
        if not alice_ratchet_pub_str:
             raise ValueError("Cannot initiate session: DR header missing dh_pub")
        alice_ratchet_pub = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(alice_ratchet_pub_str))
        dr.DHRatchet_for_bob_initial(self.x3dh.signed_pre_key_private, alice_ratchet_pub)
        
        self.sessions[partner_username] = dr
        self.db.save_session(partner_username, dr)
        self.counters.increment('x3dh_sessions_initiated_bob')
        return dr, SK

    def encrypt_message(self, partner_username: str, plaintext: str) -> dict:
        """
        Encrypts a message for a given partner.

        Args:
            partner_username: The username of the recipient.
            plaintext: The message to encrypt.

        Returns:
            A dictionary containing the encrypted message components.
        """
        if partner_username not in self.sessions:
            x3dh_header, _ = self._initiate_session_alice(partner_username)
        else:
            x3dh_header = None

        dr = self.sessions[partner_username]
        dr_header, dr_body = dr.RatchetEncrypt(plaintext.encode('utf-8'))
        self.save_contacts_to_disk()
        self.db.save_session(partner_username, dr)

        return {"x3dh_header": x3dh_header, "dr_header": dr_header, "dr_body": dr_body}

    def decrypt_message(self, partner_username: str, payload: dict) -> str | None:
        """
        Decrypts an incoming message from a partner.

        Args:
            partner_username: The username of the sender.
            payload: The encrypted message payload.

        Returns:
            The decrypted plaintext message, or None if decryption fails.
            Returns "NEEDS_BUNDLE" if a session needs to be established but
            the partner's key bundle is not available.
        """
        x3dh_header, dr_header, dr_body = payload.get("x3dh_header"), payload.get("dr_header"), payload.get("dr_body")
        try:
            if partner_username not in self.sessions:
                if not x3dh_header:
                    raise Exception("Received message without session or x3dh_header")
                if partner_username not in self.partner_bundles:
                    return "NEEDS_BUNDLE"
                self._initiate_session_bob(partner_username, x3dh_header, dr_header)
        
            dr = self.sessions[partner_username]
            plaintext_bytes = dr.RatchetDecrypt(dr_header, dr_body)
            self.save_contacts_to_disk()
            self.db.save_session(partner_username, dr)
            return plaintext_bytes.decode('utf-8')
        except InvalidTag:
            print("Could not decrypt message (Integrity Check Failed). State rolled back.")
            return None
        except Exception as e:
            print(f"An unexpected error occurred during decryption: {e}")
            return None