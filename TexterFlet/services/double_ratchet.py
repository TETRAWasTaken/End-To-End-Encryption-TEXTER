from __future__ import annotations
import hmac
import base64
from services import utils
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


def bytes_to_b64str(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')


def b64str_to_bytes(s: str) -> bytes:
    return base64.b64decode(s)


class DoubleRatchetSession:
    def __init__(self, sk: bytes):
        self.utils = utils.EncryptionUtil()
        self.MAX_SKIP = 1000
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
        self.DHs = self.utils.generate_x25519_key_pair()

    def __getstate__(self) -> dict:
        state = self.__dict__.copy()
        del state["utils"]
        if state['DHs']:
            state['DHs'] = (
                state['DHs'][0].private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                              serialization.NoEncryption()),
                state['DHs'][1].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            )
        if state['DHr_obj']:
            state['DHr_obj'] = state['DHr_obj'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return state

    def __setstate__(self, state: dict):
        if state['DHs']:
            state['DHs'] = (
                x25519.X25519PrivateKey.from_private_bytes(state['DHs'][0]),
                x25519.X25519PublicKey.from_public_bytes(state['DHs'][1])
            )
        if state['DHr_obj']:
            state['DHr_obj'] = x25519.X25519PublicKey.from_public_bytes(state['DHr_obj'])
        state['utils'] = utils.EncryptionUtil()
        self.__dict__.update(state)

    def _KDF_RK(self, rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=rk, info=b"DoubleRatchet-RootKey",
                    backend=default_backend())
        derived = hkdf.derive(dh_out)
        return derived[:32], derived[32:]

    def _KDF_CK(self, ck: bytes) -> tuple[bytes, bytes]:
        new_mk = hmac.new(ck, b'\x01', 'sha256').digest()
        new_ck = hmac.new(ck, b'\x02', 'sha256').digest()
        return new_ck, new_mk

    def DHRatchet_for_alice_initial(self, partner_spk_pub: x25519.X25519PublicKey):
        self.DHr_obj = partner_spk_pub
        self.DHr_b64 = bytes_to_b64str(
            partner_spk_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        dh_ex = self.DHs[0].exchange(self.DHr_obj)
        self.RK, self.CKs = self._KDF_RK(self.RK, dh_ex)

    def DHRatchet_for_bob_initial(self, spk_private_key: x25519.X25519PrivateKey,
                                  partner_dh_pub_obj: x25519.X25519PublicKey):
        self.DHr_obj = partner_dh_pub_obj
        self.DHr_b64 = bytes_to_b64str(
            partner_dh_pub_obj.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        dh_ex_recv = spk_private_key.exchange(self.DHr_obj)
        self.RK, self.CKr = self._KDF_RK(self.RK, dh_ex_recv)
        dh_ex_send = self.DHs[0].exchange(self.DHr_obj)
        self.RK, self.CKs = self._KDF_RK(self.RK, dh_ex_send)

    def _DHRatchet_symmetric_step(self, partner_dh_pub_obj: x25519.X25519PublicKey):
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0
        self.DHr_obj = partner_dh_pub_obj
        self.DHr_b64 = bytes_to_b64str(
            partner_dh_pub_obj.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        dh_ex1 = self.DHs[0].exchange(self.DHr_obj)
        self.RK, self.CKr = self._KDF_RK(self.RK, dh_ex1)
        self.DHs = self.utils.generate_x25519_key_pair()
        dh_ex2 = self.DHs[0].exchange(self.DHr_obj)
        self.RK, self.CKs = self._KDF_RK(self.RK, dh_ex2)

    def _TrySkippedMessageKeys(self, header: dict, body: dict) -> bytes | None:
        key = (header["dh_pub"], header["n"])
        if key in self.MKSKIPPED:
            mk = self.MKSKIPPED.pop(key)
            try:
                plaintext = self.utils.decrypt_aes_gcm(mk, b64str_to_bytes(body["ciphertext"]),
                                                       b64str_to_bytes(body["nonce"]), b64str_to_bytes(body["tag"]))
                return plaintext
            except InvalidTag:
                raise
        return None

    def _SkipMessageKeys(self, until: int):
        if self.Nr + self.MAX_SKIP < until:
            raise Exception("Skipped too many messages")
        if self.CKr is not None:
            while self.Nr < until:
                self.CKr, mk = self._KDF_CK(self.CKr)
                self.MKSKIPPED[(self.DHr_b64, self.Nr)] = mk
                self.Nr += 1

    def RatchetEncrypt(self, plaintext: bytes) -> tuple[dict, dict]:
        if self.CKs is None:
            raise Exception("Cannot encrypt: Sending chain key is not initialized.")
        self.CKs, mk = self._KDF_CK(self.CKs)
        header = {
            "dh_pub": bytes_to_b64str(
                self.DHs[1].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
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
        state_backup = {k: v for k, v in self.__dict__.items() if k not in ['utils']}
        state_backup["MKSKIPPED"] = self.MKSKIPPED.copy()
        try:
            plaintext = self._TrySkippedMessageKeys(header, body)
            if plaintext is not None:
                return plaintext

            if header["dh_pub"] != self.DHr_b64:
                self._SkipMessageKeys(header["pn"])
                self._DHRatchet_symmetric_step(
                    x25519.X25519PublicKey.from_public_bytes(b64str_to_bytes(header["dh_pub"])))

            if header["n"] < self.Nr:
                raise InvalidTag("Received an old, out-of-order message that could not be decrypted.")

            self._SkipMessageKeys(header["n"])
            if self.CKr is None:
                raise Exception("Cannot decrypt: Receiving chain key is not initialized.")
            self.CKr, mk = self._KDF_CK(self.CKr)
            self.Nr += 1
            return self.utils.decrypt_aes_gcm(mk, b64str_to_bytes(body["ciphertext"]), b64str_to_bytes(body["nonce"]),
                                              b64str_to_bytes(body["tag"]))
        except Exception:
            self.__dict__.update(state_backup)
            self.MKSKIPPED = state_backup["MKSKIPPED"]
            raise