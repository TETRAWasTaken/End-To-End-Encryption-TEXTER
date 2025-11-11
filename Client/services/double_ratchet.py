# Client/services/double_ratchet.py
import hmac
import base64
from Client.services import utils
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# --- b64 helpers ---
def bytes_to_b64str(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')


def b64str_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))


class DoubleRatchetSession:
    """
    Manages the Double Ratchet state for a single conversation.
    Implements pseudocode from doubleratchet.pdf (Section 3) [cite: 591-708].
    """

    def __init__(self, sk: bytes, partner_dh_pub: x25519.X25519PublicKey = None):
        """
        Initialize the session.
        - 'sk': The 32-byte shared secret from X3DH.
        - 'partner_dh_pub': The partner's public key (IK or SPK)
                           This determines who starts as Alice/Bob.
        """
        print("Initializing Double Ratchet session...")
        self.utils = utils.EncryptionUtil()
        self.MAX_SKIP = 1000  # Max skipped messages

        # State variables [cite: 404-411]
        self.DHs = self.utils.generate_x25519_key_pair()  # Our current ratchet keypair
        self.DHr_obj = None  # Partner's ratchet key (object)
        self.DHr_b64 = None  # Partner's ratchet key (b64 string)
        self.RK = sk  # Root Key (from X3DH)
        self.CKs = None  # Sending Chain Key
        self.CKr = None  # Receiving Chain Key
        self.Ns = 0  # Sending message number
        self.Nr = 0  # Receiving message number
        self.PN = 0  # Previous chain length
        self.MKSKIPPED = {}  # Skipped message keys [cite: 410]

        if partner_dh_pub:
            # We are Alice (the initiator), we have a key to send to
            # Or we are Bob, receiving the first message.
            # The logic inside _DHRatchet handles both cases.
            self._DHRatchet(partner_dh_pub)


    def __getstate__(self):
        """
        Returns a serialisable state dictionary for pickle
        """
        state = self.__dict__.copy()
        del state["utils"]

        if state['DHs']:
            state['DHs'] = (
                state['DHs'][0].private_bytes_raw(),
                state['DHs'][1].public_bytes_raw()
            )
        if state['DHr_obj']:
            state['DHr_obj'] = state['DHr_obj'].public_bytes_raw()

        return state

    def __setstate__(self, state):
        """
        Restores state from a serialised dictionary
        """

        if state['DHs']:
            state['DHs'] = (
                x25519.X25519PrivateKey.from_private_bytes(state['DHs'][0]),
                x25519.X25519PublicKey.from_public_bytes(state['DHs'][1])
            )

        if state['DHr_obj']:
            state['DHr_obj'] = x25519.X25519PublicKey.from_public_bytes(state['DHr_obj'])

        state['utils'] = utils.EncryptionUtil()

        self.__dict__.update(state)

    def _KDF_RK(self, rk, dh_out):
        """KDF for the Root Chain [cite: 597]"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 for new RK, 32 for new CK
            salt=rk,
            info=b"DoubleRatchet-RootKey",
            backend=default_backend()
        )
        derived = hkdf.derive(dh_out)
        return derived[:32], derived[32:]  # (new_RK, new_CK)

    def _KDF_CK(self, ck):
        """KDF for the Sending/Receiving Chain [cite: 598]"""
        # HMAC-based KDF (as recommended in PDF) [cite: 941]
        new_mk = hmac.new(ck, b'\x01', 'sha256').digest()
        new_ck = hmac.new(ck, b'\x02', 'sha256').digest()
        return new_ck, new_mk

    def _DHRatchet(self, partner_dh_pub_obj: x25519.X25519PublicKey):
        """Performs a DH ratchet step [cite: 696-707]"""
        if self.CKs is None and self.CKr is None:
            # This is the first ratchet step for either Alice or Bob.
            self.PN = 0
            self.Ns = 0
            self.Nr = 0
            self.DHr_obj = partner_dh_pub_obj
            self.DHr_b64 = bytes_to_b64str(partner_dh_pub_obj.public_bytes_raw())
            dh_ex = self.DHs[0].exchange(self.DHr_obj)
            self.RK, self.CKs = self._KDF_RK(self.RK, dh_ex)
            # Alice does not generate a new key pair here. She uses the current one until she sends a message.
        else:
            # This is a normal ratchet step for a received message.
            self.PN = self.Ns
            self.Ns = 0
            self.Nr = 0
            self.DHr_obj = partner_dh_pub_obj
            self.DHr_b64 = bytes_to_b64str(partner_dh_pub_obj.public_bytes_raw())

            # KDF new RK and CKr from old RK and new DH output, then generate a new sending key pair for our *next* message
            dh_ex1 = self.DHs[0].exchange(self.DHr_obj)
            self.RK, self.CKr = self._KDF_RK(self.RK, dh_ex1)
            self.DHs = self.utils.generate_x25519_key_pair()  # Our new key pair

    def _TrySkippedMessageKeys(self, header: dict, body: dict):
        """
        Implements TrySkippedMessageKeys pseudocode [cite: 679-685]
        Checks if the message is one we've skipped.
        """
        key = (header["dh_pub"], header["n"])
        if key in self.MKSKIPPED:
            mk = self.MKSKIPPED[key]
            del self.MKSKIPPED[key]

            # Decrypt using the body
            ciphertext = b64str_to_bytes(body["ciphertext"])
            nonce = b64str_to_bytes(body["nonce"])
            tag = b64str_to_bytes(body["tag"])

            plaintext = self.utils.decrypt_aes_gcm(mk, ciphertext, nonce, tag)
            return plaintext
        else:
            return None

    def _SkipMessageKeys(self, until):
        """
        Implements SkipMessageKeys pseudocode [cite: 686-695]
        Steps the receiving chain forward and stores keys for skipped messages.
        """
        if self.Nr + self.MAX_SKIP < until:
            raise Exception("Skipped too many messages")

        if self.CKr is not None:
            while self.Nr < until:
                self.CKr, mk = self._KDF_CK(self.CKr)
                key = (self.DHr_b64, self.Nr)  # Key by (pubkey_str, msg_num)
                self.MKSKIPPED[key] = mk
                self.Nr += 1

    def RatchetEncrypt(self, plaintext: bytes) -> tuple[dict, dict]:
        """Encrypts a message [cite: 654-658]"""
        self.CKs, mk = self._KDF_CK(self.CKs)

        header = {
            "dh_pub": bytes_to_b64str(self.DHs[1].public_bytes_raw()),
            "pn": self.PN,
            "n": self.Ns
        }
        self.Ns += 1

        ciphertext, nonce, tag = self.utils.encrypt_aes_gcm(mk, plaintext)

        encrypted_body = {
            "ciphertext": bytes_to_b64str(ciphertext),
            "nonce": bytes_to_b64str(nonce),
            "tag": bytes_to_b64str(tag)
        }

        return header, encrypted_body

    def RatchetDecrypt(self, header: dict, body: dict) -> bytes:
        """Decrypts a message [cite: 660-678]"""

        # Check if this is a skipped message
        plaintext = self._TrySkippedMessageKeys(header, body)
        if plaintext is not None:
            return plaintext

        # Not a skipped message, so proceed
        partner_dh_pub_str = header["dh_pub"]
        partner_dh_pub_bytes = b64str_to_bytes(partner_dh_pub_str)
        partner_dh_pub_obj = x25519.X25519PublicKey.from_public_bytes(partner_dh_pub_bytes)

        # Check if this is a new ratchet key from partner
        if partner_dh_pub_str != self.DHr_b64:
            # This is a new ratchet, store skipped keys from OLD chain
            self._SkipMessageKeys(header["pn"])
            # Perform DH ratchet step
            self._DHRatchet(partner_dh_pub_obj)
            # Store skipped keys from NEW chain
            self._SkipMessageKeys(header["n"])
        else:
            # Same ratchet, just store skipped keys
            self._SkipMessageKeys(header["n"])

        # We are now at the correct message number, derive the key and decrypt
        self.CKr, mk = self._KDF_CK(self.CKr)
        self.Nr += 1

        ciphertext = b64str_to_bytes(body["ciphertext"])
        nonce = b64str_to_bytes(body["nonce"])
        tag = b64str_to_bytes(body["tag"])

        plaintext = self.utils.decrypt_aes_gcm(mk, ciphertext, nonce, tag)
        return plaintext