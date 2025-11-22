# Client/services/double_ratchet.py
import hmac
import base64
from Client.services import utils
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


# --- b64 helpers ---
def bytes_to_b64str(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')


def b64str_to_bytes(s: str) -> bytes:
    return base64.b64decode(s)


class DoubleRatchetSession:
    """
    Manages the Double Ratchet state for a single conversation.
    This implementation is now more closely aligned with the specification,
    separating Alice's initial step from Bob's and subsequent symmetric steps.
    """

    def __init__(self, sk: bytes):
        """
        Initializes a session with a shared secret.
        - 'sk': The 32-byte shared secret from X3DH.
        """
        self.utils = utils.EncryptionUtil()
        self.counters = utils.CryptoCounters()
        self.MAX_SKIP = 1000

        # State variables
        self.DHs: tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey] | None = None
        self.DHr_obj: x25519.X25519PublicKey | None = None
        self.DHr_b64: str | None = None
        self.RK: bytes = sk
        self.CKs: bytes | None = None
        self.CKr: bytes | None = None
        self.Ns: int = 0
        self.Nr: int = 0
        self.PN: int = 0
        self.MKSKIPPED: dict = {}

        # Generate our first ratchet key pair immediately
        self.DHs = self.utils.generate_x25519_key_pair()

    def __getstate__(self):
        """Returns a serialisable state dictionary for pickle."""
        state = self.__dict__.copy()
        del state["utils"]
        del state["counters"]

        if state['DHs']:
            state['DHs'] = (
                state['DHs'][0].private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                ),
                state['DHs'][1].public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
        if state['DHr_obj']:
            state['DHr_obj'] = state['DHr_obj'].public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        return state

    def __setstate__(self, state):
        """Restores state from a serialised dictionary."""
        if state['DHs']:
            state['DHs'] = (
                x25519.X25519PrivateKey.from_private_bytes(state['DHs'][0]),
                x25519.X25519PublicKey.from_public_bytes(state['DHs'][1])
            )
        if state['DHr_obj']:
            state['DHr_obj'] = x25519.X25519PublicKey.from_public_bytes(state['DHr_obj'])

        state['utils'] = utils.EncryptionUtil()
        state['counters'] = utils.CryptoCounters()
        self.__dict__.update(state)

    def _KDF_RK(self, rk, dh_out):
        """KDF for the Root Chain."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=rk,
            info=b"DoubleRatchet-RootKey",
            backend=default_backend()
        )
        derived = hkdf.derive(dh_out)
        return derived[:32], derived[32:]

    def _KDF_CK(self, ck):
        """KDF for the Sending/Receiving Chain."""
        new_mk = hmac.new(ck, b'\x01', 'sha256').digest()
        new_ck = hmac.new(ck, b'\x02', 'sha256').digest()
        return new_ck, new_mk

    def DHRatchet_for_alice_initial(self, partner_spk_pub: x25519.X25519PublicKey):
        """
        Performs the initial DH ratchet step for the initiator (Alice).
        This uses the partner's Signed Pre-Key.
        """
        self.DHr_obj = partner_spk_pub
        self.DHr_b64 = bytes_to_b64str(partner_spk_pub.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ))
        dh_ex = self.DHs[0].exchange(self.DHr_obj)
        self.RK, self.CKs = self._KDF_RK(self.RK, dh_ex)

    def DHRatchet_for_bob_initial(self, spk_private_key: x25519.X25519PrivateKey, partner_dh_pub_obj: x25519.X25519PublicKey):
        """
        Performs the initial DH ratchet step for the responder (Bob).
        Bob must use his Signed Pre-Key (private) to synchronize with Alice's first step.
        Then, he initializes his sending chain using his generated DHs (B1).
        """
        self.DHr_obj = partner_dh_pub_obj
        self.DHr_b64 = bytes_to_b64str(partner_dh_pub_obj.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ))

        # 1. Derive Receiving Chain (CKr) corresponding to Alice's sending chain
        # DH(SPK_priv, A1_pub)
        dh_ex_recv = spk_private_key.exchange(self.DHr_obj)
        self.RK, self.CKr = self._KDF_RK(self.RK, dh_ex_recv)

        # 2. Derive Sending Chain (CKs) for Bob's future messages
        # DH(B1_priv, A1_pub)
        # self.DHs was initialized in __init__
        dh_ex_send = self.DHs[0].exchange(self.DHr_obj)
        self.RK, self.CKs = self._KDF_RK(self.RK, dh_ex_send)

    def _DHRatchet_symmetric_step(self, partner_dh_pub_obj: x25519.X25519PublicKey):
        """Performs a symmetric DH ratchet step for a received message."""
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0
        self.DHr_obj = partner_dh_pub_obj
        self.DHr_b64 = bytes_to_b64str(partner_dh_pub_obj.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ))

        # KDF new RK and CKr from old RK and new DH output
        dh_ex1 = self.DHs[0].exchange(self.DHr_obj)
        new_rk, self.CKr = self._KDF_RK(self.RK, dh_ex1)
        self.RK = new_rk
        # Generate a new sending key pair for our *next* message
        self.DHs = self.utils.generate_x25519_key_pair()
        
        # KDF a new CKs as well
        dh_ex2 = self.DHs[0].exchange(self.DHr_obj)
        new_rk, self.CKs = self._KDF_RK(self.RK, dh_ex2)
        self.RK = new_rk

    def _TrySkippedMessageKeys(self, header: dict, body: dict):
        """Checks if the message is one we've skipped."""
        key = (header["dh_pub"], header["n"])
        if key in self.MKSKIPPED:
            mk = self.MKSKIPPED[key]
            del self.MKSKIPPED[key]
            ciphertext = b64str_to_bytes(body["ciphertext"])
            nonce = b64str_to_bytes(body["nonce"])
            tag = b64str_to_bytes(body["tag"])
            try:
                plaintext = self.utils.decrypt_aes_gcm(mk, ciphertext, nonce, tag)
                self.counters.increment('skipped_messages_processed')
                return plaintext
            except InvalidTag:
                # This should not happen for a skipped key, but handle defensively
                self.counters.increment('decryption_failures_invalid_tag')
                raise
        return None

    def _SkipMessageKeys(self, until):
        """Steps the receiving chain forward and stores keys for skipped messages."""
        if self.Nr + self.MAX_SKIP < until:
            raise Exception("Skipped too many messages")
        if self.CKr is not None:
            while self.Nr < until:
                self.CKr, mk = self._KDF_CK(self.CKr)
                key = (self.DHr_b64, self.Nr)
                self.MKSKIPPED[key] = mk
                self.Nr += 1

    def RatchetEncrypt(self, plaintext: bytes) -> tuple[dict, dict]:
        """Encrypts a message."""
        if self.CKs is None:
            raise Exception("Cannot encrypt: Sending chain key is not initialized.")
        
        self.CKs, mk = self._KDF_CK(self.CKs)
        header = {
            "dh_pub": bytes_to_b64str(self.DHs[1].public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )),
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
        """Decrypts a subsequent (not the first) message."""
        plaintext = self._TrySkippedMessageKeys(header, body)
        if plaintext is not None:
            return plaintext

        # --- State Backup for Rollback ---
        state_backup = {
             "RK": self.RK,
             "CKr": self.CKr,
             "CKs": self.CKs,
             "Nr": self.Nr,
             "Ns": self.Ns,
             "PN": self.PN,
             "DHr_obj": self.DHr_obj,
             "DHr_b64": self.DHr_b64,
             "DHs": self.DHs, 
             "MKSKIPPED": self.MKSKIPPED.copy() 
        }

        try:
            # --- Handle out-of-order (old) messages ---
            # If the message is from a previous ratchet, we can't decrypt it.
            if header["dh_pub"] != self.DHr_b64:
                # Note: We compare header['pn'] (previous chain length) with our Nr. 
                # Logic fixed: self._SkipMessageKeys uses self.Nr vs target.
                
                self._SkipMessageKeys(header["pn"])
                partner_dh_pub_obj = x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(header["dh_pub"]))
                self._DHRatchet_symmetric_step(partner_dh_pub_obj)
        
            # If the message is from the current ratchet, but an old message number, we can't decrypt it.
            if header["n"] < self.Nr:
                self.counters.increment('old_messages_discarded')
                raise InvalidTag("Received an old, out-of-order message that could not be decrypted.")

            self._SkipMessageKeys(header["n"])
        
            if self.CKr is None:
                 raise Exception("Cannot decrypt: Receiving chain key is not initialized.")
        
            self.CKr, mk = self._KDF_CK(self.CKr)
            self.Nr += 1
            ciphertext = b64str_to_bytes(body["ciphertext"])
            nonce = b64str_to_bytes(body["nonce"])
            tag = b64str_to_bytes(body["tag"])
        
            # Attempt Decryption
            plaintext = self.utils.decrypt_aes_gcm(mk, ciphertext, nonce, tag)
            return plaintext

        except Exception:
            # ROLLBACK STATE ON FAILURE to prevent corruption
            self.RK = state_backup["RK"]
            self.CKr = state_backup["CKr"]
            self.CKs = state_backup["CKs"]
            self.Nr = state_backup["Nr"]
            self.Ns = state_backup["Ns"]
            self.PN = state_backup["PN"]
            self.DHr_obj = state_backup["DHr_obj"]
            self.DHr_b64 = state_backup["DHr_b64"]
            self.DHs = state_backup["DHs"]
            self.MKSKIPPED = state_backup["MKSKIPPED"]
            self.counters.increment('decryption_failures_invalid_tag')
            raise
