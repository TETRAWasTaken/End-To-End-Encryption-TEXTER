from Client import utils
from typing import Dict, List


class X3DH:
    """
    Implementation of the X3DH protocol (CLIENT SIDE)
    """

    def __init__(self, user_id: str):
        """
        Initialise the X3DH protocol
        :param user_id: The user id of the user
        """
        self.user_id = user_id
        self._encryption_util = utils.EncryptionUtil()

    def generate_key_bundle(self, num_one_time_keys: int = 10) -> Dict:
        """
        Generate a KeyBundle for the user

        This bundle includes a public identity key, a public signed pre-key, a public one-time pre-key,
        and a signature of the public signed pre-key.

        The corresponding private keys are generated and returned.
        """

        # Generate Identity Key pair (IK)
        self.identity_key_private, ik_public = self._encryption_util.generate_x25519_key_pair()

        # Generate Signed Pre Key (SPK)
        self.signed_pre_key_private, spk_public = self._encryption_util.generate_x25519_key_pair()

        # Generate a signature for the SPK public
        signing_key_private, _ = self._encryption_util.generate_ed25519_key_pair()
        spk_signature = signing_key_private.sign(spk_public.public_bytes())
        self.signing_key_private = signing_key_private

        # Generate One Time Pre Keys (OPKs)
        self.one_time_pre_keys_private = {}
        opk_public_dict = {}
        for i in range(num_one_time_keys):
            opk_private, opk_public = self._encryption_util.generate_x25519_key_pair()
            self.one_time_pre_keys_private[i] = opk_private
            opk_public_dict[i] = opk_public

        public_key_bundle = {
            "identity_key": ik_public,
            "signed_pre_key": spk_public,
            "signed_pre_key_signature": spk_signature,
            "one_time_pre_keys": opk_public_dict
        }

        return public_key_bundle