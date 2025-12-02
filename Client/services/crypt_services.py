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
    Wraps all X3DH and encryption logic.
    - Manages cryptographic state via an encrypted database.
    """

    def __init__(self, username: str):
        self.username = username
        self.x3dh = x3dh.X3DH(username)
        self.utils = utils.EncryptionUtil()
        self.counters = utils.CryptoCounters()

        # Get Correct Data directory
        data_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation)
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)

        # Path to our encrypted database
        db_path = os.path.join(data_dir, f"{self.username}.db")
        self.db = DatabaseService(db_path)

        # --- In-Memory State ---
        # The key derived from the user's password, stored only for this session
        self._file_key: bytes | None = None

        # Cache for partner's public bundles from server
        self.partner_bundles: Dict[str, dict] = {}

        # Dynamic state, loaded from _state_file
        self.private_opks: Dict[int, x25519.X25519PrivateKey] = {}
        self.sessions: Dict[str, DoubleRatchetSession] = {}

    # --- (Keystore encryption/decryption) ---
    def _derive_file_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000,  # <-- Set to 1000
            backend=default_backend()
        )
        return kdf.derive(password.encode("utf-8"))

    def _X3DH_KDF(self, km: bytes) -> bytes:
        F = b'\xFF' * 32
        # Per X3DH spec, salt is zeros, IKM is F || KM
        salt = b'\x00' * 32
        ikm = F + km 
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"X3DH",  # Application-specific info
            backend=default_backend()
        )
        return hkdf.derive(ikm)

    def generate_and_save_key(self, password: str) -> Dict | None:
        """
        FOR REGISTRATION:
        1. Checks if a database already exists. If so, aborts.
        2. Generates all keys.
        3. Creates and populates an encrypted database.
        4. Returns the public bundle for upload.
        """
        # --- CRITICAL SAFETY CHECK ---
        if os.path.exists(self.db._db_path):
            print(f"Registration aborted: Database for user '{self.username}' already exists.")
            return None

        public_bundle_obj = self.x3dh.generate_key_bundle()

        # 1. Derive file key and connect to DB
        salt = os.urandom(16)
        self._file_key = self._derive_file_key(password, salt)
        self.db.connect(self._file_key)
        self.db.create_tables()

        # 2. Save salt and long-term private keys to the database
        self.db.save_salt(salt)
        private_keys = self.x3dh.get_private_keys_for_saving()
        self.db.save_key("identity_key", private_keys["identity_key"])
        self.db.save_key("identity_key_dh", private_keys["identity_key_dh"])
        self.db.save_key("signed_pre_key", private_keys["signed_pre_key"])

        # 3. Save dynamic state (OPKs) to the state file
        self.private_opks = self.x3dh.one_time_pre_keys_private
        self.db.save_opks(self.private_opks)

        # Disconnect from DB
        self.db.close()

        # 4. Return the serializable PUBLIC bundle
        return self.serializable_key_bundle(public_bundle_obj)

    def load_keys_from_disk(self, password: str) -> bool:
        """
        FOR LOGIN:
        1. Derives file key from password and salt from DB.
        2. Connects to the encrypted database.
        3. Loads all keys, sessions, and state into memory.
        """
        try:
            # 1. Connect to a temporary, un-keyed DB connection to get the salt
            temp_db = DatabaseService(self.db._db_path)
            temp_db.connect(b'') # Connect without a key
            salt = temp_db.get_salt()
            temp_db.close()

            if not salt:
                print("Login failed: could not retrieve salt from database.")
                return False

            # 2. Derive the real file key and connect to the encrypted DB
            self._file_key = self._derive_file_key(password, salt)
            self.db.connect(self._file_key)

            # 3. Load long-term keys into X3DH object
            self.x3dh.load_private_keys(
                ik_priv_bytes=self.db.get_key("identity_key"),
                spk_priv_bytes=self.db.get_key("signed_pre_key"),
                ik_dh_priv_bytes=self.db.get_key("identity_key_dh")
            )

            # 4. Load dynamic state into memory
            self.private_opks = self.db.get_all_opks()
            self.sessions = self.db.get_all_sessions()

            return True

        except Exception as e:
            print(f"Database loading failed (bad password or corrupted file?): {e}")
            self._file_key = None  # Clear key on failure
            if self.db.is_connected():
                self.db.close()
            return False

    def save_contacts_to_disk(self):
        """Saves the current list of session partners as contacts."""
        if self.db.is_connected():
            contacts = list(self.sessions.keys())
            self.db.save_contacts(contacts)

    def load_contacts_from_disk(self) -> list:
        """Loads the contact list from disk."""
        if self.db.is_connected():
            return self.db.get_all_contacts()
        return []

    def serializable_key_bundle(self, bundle: dict) -> Dict:
        """
        Serializes public key bytes into base64 strings
        """
        return {
            "identity_key": bytes_to_b64str(bundle["identity_key"].public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )),
            "identity_key_dh": bytes_to_b64str(bundle["identity_key_dh"].public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )),
            "signed_pre_key": bytes_to_b64str(bundle["signed_pre_key"].public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )),
            "signature": bytes_to_b64str(bundle["signed_pre_key_signature"]),
            "one_time_pre_keys": {
                str(key_id): bytes_to_b64str(opk.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ))
                for key_id, opk in bundle["one_time_pre_keys"].items()
            }
        }

    def store_partner_bundle(self, partner_username: str, bundle_json: dict):
        """
        Stores a partner's bundle received from the server.
        """
        try:
            # --- Key Deserialization ---
            ik_str = bundle_json.get("identity_key")
            ik_dh_str = bundle_json.get("identity_key_dh")
            spk_str = bundle_json.get("signed_pre_key")
            sig_str = bundle_json.get("signature")

            if not all([ik_str, spk_str, sig_str]):
                self.counters.increment('bundle_validation_failures')
                raise ValueError("Received an incomplete key bundle from the server.")

            ik_bytes = b64str_to_bytes(ik_str)
            spk_bytes = b64str_to_bytes(spk_str)
            signature_bytes = b64str_to_bytes(sig_str)
            opk_bytes = b64str_to_bytes(bundle_json.get("one_time_pre_key")) if bundle_json.get("one_time_pre_key") else None

            # Ed25519 Identity Key (for verification)
            identity_key = ed25519.Ed25519PublicKey.from_public_bytes(ik_bytes)
            
            # X25519 Identity Key (for DH) - Essential for X3DH with `cryptography` lib
            if ik_dh_str:
                identity_key_dh = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(ik_dh_str))
            else:
                raise ValueError("Partner bundle missing X25519 Identity Key (identity_key_dh)")

            signed_pre_key = x25519.X25519PublicKey.from_public_bytes(spk_bytes)

            try:
                identity_key.verify(signature_bytes, spk_bytes)
            except InvalidSignature:
                self.counters.increment('bundle_validation_failures')
                print(f"CRITICAL: Invalid signature on pre-key for {partner_username}. Bundle rejected.")
                return

            # Deserialize the bundle from b64 strings back into cryptography objects
            deserialized_bundle = {
                "identity_key": identity_key, 
                "identity_key_dh": identity_key_dh, # Store DH Key
                "signed_pre_key": signed_pre_key,
                "one_time_pre_key": x25519.X25519PublicKey.from_public_bytes(opk_bytes) if opk_bytes else None,
                "one_time_key_id": bundle_json.get("one_time_key_id")
            }
            self.partner_bundles[partner_username] = deserialized_bundle
            self.partner_bundles[partner_username] = deserialized_bundle
        except Exception as e:
            print(f"Error storing or verifying partner bundle for {partner_username}: {e}")

    def _initiate_session_alice(self, partner_username: str) -> tuple[dict, bytes]:
        """
        Performs the X3DH "Alice" role
        """
        if partner_username not in self.partner_bundles:
            raise Exception(f"No bundle for {partner_username}")

        bundle = self.partner_bundles[partner_username]

        # Use the partner's X25519 Identity Key for DH
        p_ik_dh = bundle['identity_key_dh']
        
        p_spk_pub = bundle['signed_pre_key']
        p_opk_pub = None
        opk_id = bundle.get("one_time_key_id")
        if opk_id is not None and bundle.get("one_time_pre_key"):
            p_opk_pub = bundle["one_time_pre_key"]

        # Alice's Ephemeral Key
        ek_priv, ek_pub = self.utils.generate_x25519_key_pair()
        
        # Alice's Identity Key (DH)
        ik_priv = self.x3dh.identity_key_dh_private

        DH1 = ik_priv.exchange(p_spk_pub)
        DH2 = ek_priv.exchange(p_ik_dh)
        DH3 = ek_priv.exchange(p_spk_pub)

        if p_opk_pub:
            DH4 = ek_priv.exchange(p_opk_pub)
            km = DH1 + DH2 + DH3 + DH4
        else:
            km = DH1 + DH2 + DH3

        SK = self._X3DH_KDF(km)

        # Create a new session and save it
        dr = DoubleRatchetSession(SK)
        dr.DHRatchet_for_alice_initial(p_spk_pub)
        self.sessions[partner_username] = dr
        self.db.save_session(partner_username, dr) # Save new session to DB
        self.counters.increment('x3dh_sessions_initiated_alice')

        x3dh_header = {
            "ik_a": bytes_to_b64str(ik_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )),
            "ek_a": bytes_to_b64str(ek_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )),
            "opk_id": opk_id
        }
        return x3dh_header, SK

    def _initiate_session_bob(self, partner_username: str, x3dh_header: dict, dr_header: dict) -> tuple[DoubleRatchetSession, bytes]:

        """Performs the X3DH "Bob" role [cite: 945-954]"""

        p_ik_str = x3dh_header.get('ik_a')
        p_ek_str = x3dh_header.get('ek_a')

        if not p_ik_str or not p_ek_str:
            raise ValueError("Received incomplete X3DH header from partner.")

        # Partner's IK is already X25519 (sent by Alice)
        p_ik_pub = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(p_ik_str))
        p_ek_pub = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(p_ek_str))
        opk_id = x3dh_header.get('opk_id')

        # Bob's Keys
        ik_priv = self.x3dh.identity_key_dh_private # Bob's X25519 Identity Key
        spk_priv = self.x3dh.signed_pre_key_private
        opk_priv = None

        if opk_id is not None:
            opk_priv = self.db.pop_opk(int(opk_id))
            if not opk_priv:
                print(f"Warning: Alice used OPK {opk_id}, but we don't have it.")

        DH1 = spk_priv.exchange(p_ik_pub)
        DH2 = ik_priv.exchange(p_ek_pub)
        DH3 = spk_priv.exchange(p_ek_pub)

        if opk_priv:
            DH4 = opk_priv.exchange(p_ek_pub)
            km = DH1 + DH2 + DH3 + DH4
        else:
            km = DH1 + DH2 + DH3

        SK = self._X3DH_KDF(km)

        # Create a new "Bob" session
        dr = DoubleRatchetSession(SK)
        
        # --- Perform Bob's initial Ratchet Step (Synchronization) ---
        # Extract Alice's initial Ratchet Key (A1) from the DR header
        alice_ratchet_pub_str = dr_header.get("dh_pub")
        if not alice_ratchet_pub_str:
             raise ValueError("Cannot initiate session: DR header missing dh_pub")

        alice_ratchet_pub = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(alice_ratchet_pub_str))

        # Initialize the ratchet using our SPK private key and Alice's Ratchet Public Key
        dr.DHRatchet_for_bob_initial(self.x3dh.signed_pre_key_private, alice_ratchet_pub)
        
        self.sessions[partner_username] = dr
        self.db.save_session(partner_username, dr) # Save new session to DB
        self.counters.increment('x3dh_sessions_initiated_bob')

        return dr, SK

    def encrypt_message(self, partner_username: str, plaintext: str) -> dict:
        """
        Encrypts a message. If it's the first message,
        it performs the X3DH handshake first.
        """
        x3dh_header = None
        if partner_username not in self.sessions:
            # This will raise an exception if the bundle isn't loaded yet, 
            # which is handled by AppController checks.
            x3dh_header, sk = self._initiate_session_alice(partner_username)

        dr = self.sessions[partner_username]
        dr_header, dr_body = dr.RatchetEncrypt(plaintext.encode('utf-8'))

        self.save_contacts_to_disk()
        self.db.save_session(partner_username, dr) # Update session state in DB

        return {
            "x3dh_header": x3dh_header,
            "dr_header": dr_header,
            "dr_body": dr_body
        }

    def decrypt_message(self, partner_username: str, payload: dict) -> str:
        """
        Decrypts an incoming message payload.
        """        """
        Decrypts an incoming message payload.
        """
        x3dh_header = payload.get("x3dh_header")
        dr_header = payload.get("dr_header")
        dr_body = payload.get("dr_body")

        try:
            if partner_username not in self.sessions:
                if not x3dh_header:
                    raise Exception("Received message without session or x3dh_header")

                if partner_username not in self.partner_bundles:
                    return "NEEDS_BUNDLE"

                # Pass dr_header here so Bob can sync the ratchet
                dr, sk = self._initiate_session_bob(partner_username, x3dh_header, dr_header)
        
            dr = self.sessions[partner_username]
            plaintext_bytes = dr.RatchetDecrypt(dr_header, dr_body)

            self.save_contacts_to_disk()
            self.db.save_session(partner_username, dr) # Update session state in DB

            return plaintext_bytes.decode('utf-8')
    
        except InvalidTag:
            print("Could not decrypt message (Integrity Check Failed). State rolled back.")
            return None
        except Exception as e:
            print(f"An unexpected error occurred during decryption: {e}")
            return None
