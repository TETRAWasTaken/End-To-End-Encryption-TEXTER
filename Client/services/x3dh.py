from __future__ import annotations
from Client.services import utils
from typing import Dict, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519

import secrets

class X3DH:
    """
    Implementation of the X3DH protocol (CLIENT SIDE).
    This class now holds the user's cryptographic state.
    """

    def __init__(self, user_id: str):
        """
        Initialise the X3DH protocol
        :param user_id: The user id of the user
        """
        self.user_id = user_id
        self._encryption_util = utils.EncryptionUtil()

        self.identity_key_private: ed25519.Ed25519PrivateKey | None = None
        self.identity_key_dh_private: x25519.X25519PrivateKey | None = None # New DH Identity Key
        self.signed_pre_key_private: x25519.X25519PrivateKey | None = None
        self.one_time_pre_keys_private: Dict[int, x25519.X25519PrivateKey] = {}

    def generate_key_bundle(self, num_one_time_keys: int = 10) -> Dict:
        """
        Generate a KeyBundle for the user.
        This now populates the class attributes and returns
        ONLY the public key bundle.
        """

        # Generate Identity Key pair (IK) as an Ed25519 key for signing.
        self.identity_key_private, ik_public = self._encryption_util.generate_ed25519_key_pair()

        # Generate Identity Key pair for DH (X25519) - The "Dual" Key
        self.identity_key_dh_private, ik_dh_public = self._encryption_util.generate_x25519_key_pair()

        # Generate Signed Pre Key (SPK)
        self.signed_pre_key_private, spk_public = self._encryption_util.generate_x25519_key_pair() 

        # Sign the SPK public key with the Identity Key (Signing).
        spk_signature = self.identity_key_private.sign(spk_public.public_bytes(encoding=utils.serialization.Encoding.Raw, format=utils.serialization.PublicFormat.Raw))

        # Generate One Time Pre Keys (OPKs)
        self.one_time_pre_keys_private = {}
        opk_public_dict = {}
        for i in range(num_one_time_keys):
            opk_private, opk_public = self._encryption_util.generate_x25519_key_pair() 
            opk_id = secrets.randbits(31) # Generate a random 31-bit integer for the ID
            self.one_time_pre_keys_private[opk_id] = opk_private
            opk_public_dict[opk_id] = opk_public

        public_key_bundle = {
            "identity_key": ik_public,
            "identity_key_dh": ik_dh_public, # Add DH key to bundle
            "signed_pre_key": spk_public,
            "signed_pre_key_signature": spk_signature,
            "one_time_pre_keys": opk_public_dict
        }

        return public_key_bundle

    def get_private_keys_for_saving(self) -> Dict:
        """
        Returns a dict of raw private keys for serialization
        after generation.
        """
        if not all([self.identity_key_private, self.signed_pre_key_private, self.identity_key_dh_private]):
            raise Exception("Private keys not generated or loaded.")

        return {
            "identity_key": self.identity_key_private.private_bytes(
                encoding=utils.serialization.Encoding.Raw,
                format=utils.serialization.PrivateFormat.Raw,
                encryption_algorithm=utils.serialization.NoEncryption()
            ),
            "identity_key_dh": self.identity_key_dh_private.private_bytes(
                encoding=utils.serialization.Encoding.Raw,
                format=utils.serialization.PrivateFormat.Raw,
                encryption_algorithm=utils.serialization.NoEncryption()
            ),
            "signed_pre_key": self.signed_pre_key_private.private_bytes(
                encoding=utils.serialization.Encoding.Raw,
                format=utils.serialization.PrivateFormat.Raw,
                encryption_algorithm=utils.serialization.NoEncryption()
            ),
            "one_time_pre_keys": {
                key_id: opk.private_bytes(
                    encoding=utils.serialization.Encoding.Raw,
                    format=utils.serialization.PrivateFormat.Raw,
                    encryption_algorithm=utils.serialization.NoEncryption()
                )
                for key_id, opk in self.one_time_pre_keys_private.items()
            }
        }

    def load_private_keys(self, ik_priv_bytes, spk_priv_bytes, ik_dh_priv_bytes=None):
        """
        Loads existing private keys from raw bytes.
        Used after login to re-populate the object.
        """
        self.identity_key_private = ed25519.Ed25519PrivateKey.from_private_bytes(ik_priv_bytes)
        self.signed_pre_key_private = x25519.X25519PrivateKey.from_private_bytes(spk_priv_bytes)
        if ik_dh_priv_bytes:
            self.identity_key_dh_private = x25519.X25519PrivateKey.from_private_bytes(ik_dh_priv_bytes)
        print("Successfully loaded private keys into X3DH object.")