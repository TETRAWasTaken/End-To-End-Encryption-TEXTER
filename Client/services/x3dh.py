from Client.services import utils
from typing import Dict, Tuple


class X3DH:
    """
    Implementation of the database protocol (CLIENT SIDE)
    """

    def __init__(self, user_id: str):
        """
        Initialise the database protocol
        :param user_id: The user id of the user
        """
        self.user_id = user_id
        self._encryption_util = utils.EncryptionUtil()

    def generate_key_bundle(self, num_one_time_keys: int = 10) -> Tuple[Dict, Dict]:
        """
        Generate a KeyBundle for the user

        This bundle includes a public identity key, a public signed pre-key, a public one-time pre-key,
        and a signature of the public signed pre-key.

        The corresponding private keys are generated and returned.
        """

        # Generate Identity Key pair (IK)
        identity_key_private, ik_public = self._encryption_util.generate_x25519_key_pair()

        # Generate Signed Pre Key (SPK)
        signed_pre_key_private, spk_public = self._encryption_util.generate_x25519_key_pair()

        # Generate a signature for the SPK public
        signing_key_private, _ = self._encryption_util.generate_ed25519_key_pair()
        spk_signature = signing_key_private.sign(spk_public.public_bytes())

        # Generate One Time Pre Keys (OPKs)
        one_time_pre_keys_private = {}
        opk_public_dict = {}
        for i in range(num_one_time_keys):
            opk_private, opk_public = self._encryption_util.generate_x25519_key_pair()
            one_time_pre_keys_private[i] = opk_private
            opk_public_dict[i] = opk_public

        public_key_bundle = {
            "identity_key": ik_public,
            "signed_pre_key": spk_public,
            "signed_pre_key_signature": spk_signature,
            "one_time_pre_keys": opk_public_dict
        }
        private_key_bundle = {
            "identity_key": identity_key_private,
            "signed_pre_key": signed_pre_key_private,
            "signing_key": signing_key_private,
            "one_time_pre_keys": one_time_pre_keys_private
        }

        return public_key_bundle, private_key_bundle