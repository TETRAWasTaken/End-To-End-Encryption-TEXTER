from __future__ import annotations
import os
import json
import pickle  # We need pickle for the non-JSON-serializable session objects
from Client.services import x3dh, utils
from Client.services.double_ratchet import DoubleRatchetSession, bytes_to_b64str, b64str_to_bytes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from typing import Dict


class CryptServices:
    """
    Wraps all X3DH and encryption logic.
    - Manages a password-encrypted keystore for long-term keys.
    - Manages a password-encrypted state file for dynamic state.
    """

    def __init__(self, username: str):
        self.username = username
        self.x3dh = x3dh.X3DH(username)
        self.utils = utils.EncryptionUtil()

        # Paths to our two protected files
        self._key_file = f"{self.username}_keystore.json"
        self._state_file = f"{self.username}_statestore.json"
        self._contacts_file = f"{self.username}_contacts.json"

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
        ikm = F + km
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'\x00' * 32,  # Zero-filled salt
            info=b"X3DH",  # Application-specific info
            backend=default_backend()
        )
        return hkdf.derive(ikm)

    def _save_state_file(self):
        """
        Encrypts and overwrites the _state_file with the
        current in-memory state, using the session's _file_key.
        """
        if not self._file_key:
            print("Error: Cannot save state. No file key in memory.")
            return

        print("Persisting dynamic state...")
        try:
            serialized_opks = {
                key_id: opk.private_bytes_raw()
                for key_id, opk in self.private_opks.items()
            }

            # We must use pickle because DR objects are not JSON serializable
            state_data = {
                "private_opks": serialized_opks,
                "sessions": self.sessions
            }
            plaintext_bytes = pickle.dumps(state_data)

            # Encrypt
            ciphertext, nonce, tag = self.utils.encrypt_aes_gcm(self._file_key, plaintext_bytes)

            # Write to file
            with open(self._state_file, 'w') as f:
                json.dump({
                    "nonce": bytes_to_b64str(nonce),
                    "tag": bytes_to_b64str(tag),
                    "ciphertext": bytes_to_b64str(ciphertext)
                }, f)
        except Exception as e:
            print(f"CRITICAL: Failed to save state file: {e}")

    def generate_and_save_key(self, password: str) -> Dict:
        """
        FOR REGISTRATION:
        1. Generates all keys.
        2. Creates and saves an encrypted keystore file.
        3. Creates and saves an encrypted (mostly empty) state file.
        4. Returns the public bundle for upload.
        """
        print("Generating new key bundle...")
        public_bundle_obj = self.x3dh.generate_key_bundle()

        # 1. Derive the file key
        salt = os.urandom(16)
        self._file_key = self._derive_file_key(password, salt)

        # 2. Save long-term private keys to encrypted keystore
        private_keys = {
            "identity_key": bytes_to_b64str(self.x3dh.identity_key_private.private_bytes_raw()),
            "signed_pre_key": bytes_to_b64str(self.x3dh.signed_pre_key_private.private_bytes_raw()),
            "signing_key": bytes_to_b64str(self.x3dh.signing_key_private.private_bytes_raw())
        }

        plaintext_bytes = json.dumps(private_keys).encode('utf-8')
        ciphertext, nonce, tag = self.utils.encrypt_aes_gcm(self._file_key, plaintext_bytes)

        print(f"Saving encrypted private keys to {self._key_file}...")
        with open(self._key_file, 'w') as f:
            json.dump({
                "salt": bytes_to_b64str(salt),  # Store the salt
                "nonce": bytes_to_b64str(nonce),
                "tag": bytes_to_b64str(tag),
                "ciphertext": bytes_to_b64str(ciphertext)
            }, f)

        # 3. Save dynamic state (OPKs) to the state file
        self.private_opks = self.x3dh.one_time_pre_keys_private
        self.sessions = {}
        self._save_state_file()
        print(f"Saved {len(self.private_opks)} private OPKs to state file.")

        # 4. Return the serializable PUBLIC bundle
        return self.serializable_key_bundle(public_bundle_obj)

    def load_keys_from_disk(self, password: str) -> bool:
        """
        FOR LOGIN:
        1. Decrypts keystore, loads long-term keys.
        2. Stores the derived _file_key in memory.
        3. Decrypts state file, loads OPKs and DR sessions.
        """
        try:
            # 1. Load Keystore (Static Keys)
            if not os.path.exists(self._key_file): return False

            with open(self._key_file, 'r') as f:
                data = json.load(f)

            salt = b64str_to_bytes(data['salt'])
            nonce = b64str_to_bytes(data['nonce'])
            tag = b64str_to_bytes(data['tag'])
            ciphertext = b64str_to_bytes(data['ciphertext'])

            # Derive and *store* the file key for this session
            self._file_key = self._derive_file_key(password, salt)

            plaintext = self.utils.decrypt_aes_gcm(self._file_key, ciphertext, nonce, tag)
            private_keys = json.loads(plaintext)

            self.x3dh.load_private_keys(
                ik_priv_bytes=b64str_to_bytes(private_keys['identity_key']),
                spk_priv_bytes=b64str_to_bytes(private_keys['signed_pre_key']),
                sign_k_priv_bytes=b64str_to_bytes(private_keys['signing_key'])
            )
            print("Successfully loaded and decrypted long-term keys.")

            # 2. Load State File (Dynamic State)
            if not os.path.exists(self._state_file):
                print("Warning: State file not found. Creating new one.")
                self.private_opks = {}
                self.sessions = {}
                self._save_state_file()
            else:
                with open(self._state_file, 'r') as f:
                    data = json.load(f)

                nonce = b64str_to_bytes(data['nonce'])
                tag = b64str_to_bytes(data['tag'])
                ciphertext = b64str_to_bytes(data['ciphertext'])

                plaintext_bytes = self.utils.decrypt_aes_gcm(self._file_key, ciphertext, nonce, tag)
                state_data = pickle.loads(plaintext_bytes)

                raw_opks = state_data.get('private_opks', {})
                self.private_opks = {
                    key_id: x25519.X25519PrivateKey.from_private_bytes(opk_bytes)
                    for key_id, opk_bytes in raw_opks.items()
                }

                self.sessions = state_data.get('sessions', {})
                print(f"Loaded {len(self.private_opks)} OPKs and {len(self.sessions)} sessions.")

            return True

        except Exception as e:
            print(f"Key loading failed (bad password?): {e}")
            self._file_key = None  # Clear key on failure
            return False

    def save_contacts_to_disk(self):
        """Saves the current list of session partners as contacts."""
        try:
            contacts = list(self.sessions.keys())
            with open(self._contacts_file, 'w') as f:
                json.dump(contacts, f)
            print(f"Saved {len(contacts)} contacts to {self._contacts_file}")
        except Exception as e:
            print(f"Error saving contacts: {e}")

    def load_contacts_from_disk(self) -> list:
        """Loads the contact list from disk."""
        if not os.path.exists(self._contacts_file):
            return []
        try:
            with open(self._contacts_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading contacts: {e}")
            return []

    def serializable_key_bundle(self, bundle: dict) -> Dict:
        """
        Serializes public key bytes into base64 strings
        """
        return {
            "identity_key": bytes_to_b64str(bundle["identity_key"].public_bytes_raw()),
            "signed_pre_key": bytes_to_b64str(bundle["signed_pre_key"].public_bytes_raw()),
            "signed_pre_key_signature": bytes_to_b64str(bundle["signed_pre_key_signature"]),
            "one_time_pre_keys": {
                str(key_id): bytes_to_b64str(opk.public_bytes_raw()) # Ensure key_id is a string
                for key_id, opk in bundle["one_time_pre_keys"].items()
            }
        }

    def store_partner_bundle(self, partner_username: str, bundle_json: dict):
        """
        Stores a partner's bundle received from the server.
        """
        self.partner_bundles[partner_username] = bundle_json
        print(f"Cached bundle for {partner_username}")

    def _initiate_session_alice(self, partner_username: str) -> tuple[dict, bytes]:
        """
        Performs the X3DH "Alice" role
        """
        if partner_username not in self.partner_bundles:
            raise Exception(f"No bundle for {partner_username}")

        bundle = self.partner_bundles[partner_username]

        p_ik_pub = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(bundle['identity_key']))
        p_spk_pub = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(bundle['signed_pre_key']))
        p_opk_pub = None
        opk_id = bundle.get('one_time_key_id')
        if opk_id is not None and bundle.get('one_time_pre_key'):
            p_opk_pub = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(bundle['one_time_pre_key']))

        ek_priv, ek_pub = self.utils.generate_x25519_key_pair()
        ik_priv = self.x3dh.identity_key_private

        DH1 = ik_priv.exchange(p_spk_pub)
        DH2 = ek_priv.exchange(p_ik_pub)
        DH3 = ek_priv.exchange(p_spk_pub)

        if p_opk_pub:
            DH4 = ek_priv.exchange(p_opk_pub)
            km = DH1 + DH2 + DH3 + DH4
        else:
            km = DH1 + DH2 + DH3

        SK = self._X3DH_KDF(km)

        # Create a new session and save it
        dr = DoubleRatchetSession(SK, partner_dh_pub=p_spk_pub)
        self.sessions[partner_username] = dr
        # We don't save here, we save in the calling public function

        x3dh_header = {
            "ik_a": bytes_to_b64str(self.x3dh.identity_key_private.public_key().public_bytes_raw()),
            "ek_a": bytes_to_b64str(ek_pub.public_bytes_raw()),
            "opk_id": opk_id  # ID of the OPK we used
        }
        return x3dh_header, SK

    def _initiate_session_bob(self, partner_username: str, x3dh_header: dict) -> tuple[DoubleRatchetSession, bytes]:

        """Performs the X3DH "Bob" role [cite: 945-954]"""

        p_ik_pub = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(x3dh_header['ik_a']))
        p_ek_pub = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(x3dh_header['ek_a']))
        opk_id = x3dh_header.get('opk_id')

        ik_priv = self.x3dh.identity_key_private
        spk_priv = self.x3dh.signed_pre_key_private
        opk_priv = None

        if opk_id is not None:
            # --- THIS IS THE FIX ---
            # Retrieve and delete the one-time key from our in-memory cache
            opk_obj = self.private_opks.pop(str(opk_id), None) # Ensure opk_id is treated as a string
            if opk_obj:
                opk_priv = opk_obj
                print(f"Used and deleted private OPK {opk_id} from memory.")
            else:
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

        # Create a new "Bob" session (no initial partner key)
        dr = DoubleRatchetSession(SK, partner_dh_pub=None)
        self.sessions[partner_username] = dr
        # We don't save here, we save in the calling public function

        return dr, SK

    def encrypt_message(self, partner_username: str, plaintext: str) -> dict:
        """
        Encrypts a message. If it's the first message,
        it performs the X3DH handshake first.
        """
        x3dh_header = None
        if partner_username not in self.sessions:
            print(f"No session for {partner_username}, initiating X3DH...")
            x3dh_header, sk = self._initiate_session_alice(partner_username)

        dr = self.sessions[partner_username]
        dr_header, dr_body = dr.RatchetEncrypt(plaintext.encode('utf-8'))

        self.save_contacts_to_disk() # Persist contacts whenever a session is used/updated
        self._save_state_file()

        return {
            "x3dh_header": x3dh_header,  # Will be None after 1st msg
            "dr_header": dr_header,
            "dr_body": dr_body
        }

    def decrypt_message(self, partner_username: str, payload: dict) -> str:
        """
        Decrypts an incoming message payload.
        If it's the first message, it performs the X3DH handshake.
        """
        x3dh_header = payload.get("x3dh_header")
        dr_header = payload.get("dr_header")
        dr_body = payload.get("dr_body")

        if partner_username not in self.sessions:
            if not x3dh_header:
                raise Exception("Received message without session or x3dh_header")

            print(f"No session for {partner_username}, processing X3DH handshake...")
            dr, sk = self._initiate_session_bob(partner_username, x3dh_header)
        else:
            dr = self.sessions[partner_username]

        plaintext_bytes = dr.RatchetDecrypt(dr_header, dr_body)

        self.save_contacts_to_disk() # Persist contacts whenever a session is used/updated
        self._save_state_file()

        return plaintext_bytes.decode('utf-8')