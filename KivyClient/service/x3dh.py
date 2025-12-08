from __future__ import annotations
from Client.services import utils
from typing import Dict, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
import secrets

class X3DH:
    """
    Implementation of the X3DH (Extended Triple Diffie-Hellman) protocol.

    This class manages the user's long-term and ephemeral keys required for
    establishing a secure session with another user. It handles the generation
    of key bundles for publishing to a server and the key agreement process
    for both the initiator and responder roles.
    """

    def __init__(self, user_id: str):
        """
        Initializes the X3DH state for a user.

        Args:
            user_id: The unique identifier for the user.
        """
        self.user_id = user_id
        self._encryption_util = utils.EncryptionUtil()

        self.identity_key_private: ed25519.Ed25519PrivateKey | None = None
        self.identity_key_dh_private: x25519.X25519PrivateKey | None = None
        self.signed_pre_key_private: x25519.X25519PrivateKey | None = None
        self.one_time_pre_keys_private: Dict[int, x25519.X25519PrivateKey] = {}

    def generate_key_bundle(self, num_one_time_keys: int = 10) -> Dict:
        """
        Generates a new public key bundle for the user.

        This method creates a new identity key, signed pre-key, and a set of
        one-time pre-keys. It populates the instance's private key attributes
        and returns a dictionary of the corresponding public keys.

        Args:
            num_one_time_keys: The number of one-time pre-keys to generate.

        Returns:
            A dictionary containing the user's public key bundle.
        """
        self.identity_key_private, ik_public = self._encryption_util.generate_ed25519_key_pair()
        self.identity_key_dh_private, ik_dh_public = self._encryption_util.generate_x25519_key_pair()
        self.signed_pre_key_private, spk_public = self._encryption_util.generate_x25519_key_pair()
        spk_signature = self.identity_key_private.sign(spk_public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))

        self.one_time_pre_keys_private = {}
        opk_public_dict = {}
        for _ in range(num_one_time_keys):
            opk_private, opk_public = self._encryption_util.generate_x25519_key_pair()
            opk_id = secrets.randbits(31)
            self.one_time_pre_keys_private[opk_id] = opk_private
            opk_public_dict[opk_id] = opk_public

        return {
            "identity_key": ik_public,
            "identity_key_dh": ik_dh_public,
            "signed_pre_key": spk_public,
            "signed_pre_key_signature": spk_signature,
            "one_time_pre_keys": opk_public_dict
        }

    def get_private_keys_for_saving(self) -> Dict[str, bytes | Dict[int, bytes]]:
        """
        Exports the user's private keys for serialization.

        Returns:
            A dictionary containing the raw bytes of the user's private keys.
        """
        if not all([self.identity_key_private, self.signed_pre_key_private, self.identity_key_dh_private]):
            raise Exception("Private keys not generated or loaded.")

        return {
            "identity_key": self.identity_key_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ),
            "identity_key_dh": self.identity_key_dh_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ),
            "signed_pre_key": self.signed_pre_key_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ),
            "one_time_pre_keys": {
                key_id: opk.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                for key_id, opk in self.one_time_pre_keys_private.items()
            }
        }

    def load_private_keys(self, ik_priv_bytes: bytes, spk_priv_bytes: bytes, ik_dh_priv_bytes: bytes | None = None):
        """
        Loads existing private keys from raw bytes.

        Args:
            ik_priv_bytes: The raw bytes of the Ed25519 identity key.
            spk_priv_bytes: The raw bytes of the X25519 signed pre-key.
            ik_dh_priv_bytes: The raw bytes of the X25519 identity key.
        """
        self.identity_key_private = ed25519.Ed25519PrivateKey.from_private_bytes(ik_priv_bytes)
        self.signed_pre_key_private = x25519.X25519PrivateKey.from_private_bytes(spk_priv_bytes)
        if ik_dh_priv_bytes:
            self.identity_key_dh_private = x25519.X25519PrivateKey.from_private_bytes(ik_dh_priv_bytes)
        print("Successfully loaded private keys into X3DH object.")

    def perform_x3dh_initiator(self, partner_bundle: Dict) -> Tuple[bytes, bytes, bytes]:
        """
        Performs the X3DH key agreement as the initiator.

        Args:
            partner_bundle: The public key bundle of the communication partner.

        Returns:
            A tuple containing the shared secret key, the ephemeral public key
            used in the exchange, and the partner's public identity key.
        """
        ek_private, ek_public = self._encryption_util.generate_x25519_key_pair()

        partner_ik_dh_public = partner_bundle["identity_key_dh"]
        partner_spk_public = partner_bundle["signed_pre_key"]
        partner_opk_public = partner_bundle["one_time_pre_key"]

        dh1 = self.identity_key_dh_private.exchange(partner_spk_public)
        dh2 = ek_private.exchange(partner_ik_dh_public)
        dh3 = ek_private.exchange(partner_spk_public)
        dh4 = ek_private.exchange(partner_opk_public)

        sk = self._encryption_util.hkdf(
            input_key_material=b"LIT" + dh1 + dh2 + dh3 + dh4,
            salt=b'\x00' * 32,
        )

        return sk, ek_public, partner_bundle["identity_key"]

    def perform_x3dh_responder(self, initial_message: Dict) -> bytes:
        """
        Performs the X3DH key agreement as the responder.

        Args:
            initial_message: A dictionary containing the initiator's public
                             identity key, ephemeral key, and the ID of the
                             one-time pre-key they used.

        Returns:
            The calculated shared secret key.
        """
        initiator_ik_public = initial_message["identity_key"]
        initiator_ek_public = initial_message["ephemeral_key"]
        opk_id_used = initial_message["opk_id"]

        dh1 = self.signed_pre_key_private.exchange(initiator_ik_public)
        dh2 = self.identity_key_dh_private.exchange(initiator_ek_public)
        dh3 = self.signed_pre_key_private.exchange(initiator_ek_public)

        opk_private = self.one_time_pre_keys_private.get(opk_id_used)
        if not opk_private:
            raise ValueError("OPK ID from initiator not found.")
        dh4 = opk_private.exchange(initiator_ek_public)

        sk = self._encryption_util.hkdf(
            input_key_material=b"LIT" + dh1 + dh2 + dh3 + dh4,
            salt=b'\x00' * 32,
        )

        return sk