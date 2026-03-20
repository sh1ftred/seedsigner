from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from embit import ec


NIP46_KIND = 24133
CONFIG_PATH = "/tmp/nostr_bunker.json"
NIP44_V2_SALT = b"nip44-v2"
NIP44_VERSION = 2
NIP44_MIN_PLAINTEXT = 1
NIP44_MAX_PLAINTEXT = 65535


class NostrBunkerError(Exception):
    pass


@dataclass
class BunkerKeypair:
    private_key_hex: str
    public_key_hex: str
    secret: str


class NostrSigner:
    def __init__(self, private_key_hex: str):
        self._private_key_hex = private_key_hex
        self._private_key = ec.PrivateKey(bytes.fromhex(private_key_hex))
        self._public_key = self._private_key.get_public_key()

    @property
    def private_key_hex(self) -> str:
        return self._private_key_hex

    @property
    def public_key_hex(self) -> str:
        return self._public_key.xonly().hex()

    @staticmethod
    def generate() -> BunkerKeypair:
        raw = secrets.token_bytes(32)
        priv = ec.PrivateKey(raw)
        pub = priv.get_public_key().xonly().hex()
        secret = secrets.token_hex(16)
        return BunkerKeypair(private_key_hex=raw.hex(), public_key_hex=pub, secret=secret)

    @staticmethod
    def serialize_event_for_id(event: Dict[str, Any]) -> str:
        data = [
            0,
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"],
        ]
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def event_id(cls, event: Dict[str, Any]) -> str:
        payload = cls.serialize_event_for_id(event).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def sign_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        event = dict(event)
        event.setdefault("pubkey", self.public_key_hex)
        event.setdefault("created_at", int(time.time()))
        event.setdefault("tags", [])
        event.setdefault("content", "")

        eid = self.event_id(event)
        sig = self._private_key.schnorr_sign(bytes.fromhex(eid)).serialize().hex()

        event["id"] = eid
        event["sig"] = sig
        return event

    @staticmethod
    def verify_event(event: Dict[str, Any]) -> bool:
        required = ["id", "pubkey", "created_at", "kind", "tags", "content", "sig"]
        if any(k not in event for k in required):
            return False

        expected = NostrSigner.event_id(event)
        if expected != event["id"]:
            return False

        pub = ec.PublicKey.from_xonly(bytes.fromhex(event["pubkey"]))
        return pub.schnorr_verify(ec.SchnorrSig(bytes.fromhex(event["sig"])), bytes.fromhex(event["id"]))

    @staticmethod
    def bunker_url(bunker_pubkey_hex: str, relay_url: str, secret: str) -> str:
        return f"bunker://{bunker_pubkey_hex}?relay={relay_url}&secret={secret}"

    @staticmethod
    def make_nip46_request(method: str, params: Any, request_id: Optional[str] = None) -> str:
        payload = {
            "id": request_id or secrets.token_hex(8),
            "method": method,
            "params": params,
        }
        return json.dumps(payload, separators=(",", ":"))

    @staticmethod
    def make_nip46_response(request_id: str, result: Any = None, error: Optional[str] = None) -> str:
        payload: Dict[str, Any] = {"id": request_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result
        return json.dumps(payload, separators=(",", ":"))

    @staticmethod
    def parse_nip46_content(content: str) -> Dict[str, Any]:
        try:
            payload = json.loads(content)
        except Exception as exc:
            raise NostrBunkerError(f"invalid JSON content: {exc}") from exc

        if not isinstance(payload, dict):
            raise NostrBunkerError("NIP-46 content must be a JSON object")
        return payload

    def make_signed_nip46_event(self, client_pubkey_hex: str, content: str, kind: int = NIP46_KIND) -> Dict[str, Any]:
        event = {
            "kind": kind,
            "content": content,
            "tags": [["p", client_pubkey_hex]],
            "created_at": int(time.time()),
            "pubkey": self.public_key_hex,
        }
        return self.sign_event(event)

    @staticmethod
    def _xonly_to_compressed_pubkey(pubkey_hex: str) -> bytes:
        if len(pubkey_hex) != 64:
            raise NostrBunkerError("invalid xonly pubkey length")
        return bytes.fromhex("02" + pubkey_hex)

    @classmethod
    def _ecdh_shared_x(cls, private_key_hex: str, peer_pubkey_hex: str) -> bytes:
        try:
            priv = crypto_ec.derive_private_key(int(private_key_hex, 16), crypto_ec.SECP256K1())
            peer = crypto_ec.EllipticCurvePublicKey.from_encoded_point(
                crypto_ec.SECP256K1(),
                cls._xonly_to_compressed_pubkey(peer_pubkey_hex),
            )
            shared_point = priv.exchange(crypto_ec.ECDH(), peer)
        except Exception as exc:
            raise NostrBunkerError(f"invalid ECDH inputs: {exc}") from exc
        if len(shared_point) == 32:
            return shared_point
        raise NostrBunkerError("unexpected shared secret length")

    @classmethod
    def get_nip44_conversation_key(cls, private_key_hex: str, peer_pubkey_hex: str) -> bytes:
        shared_x = cls._ecdh_shared_x(private_key_hex, peer_pubkey_hex)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=NIP44_V2_SALT,
            info=None,
        )
        return hkdf.derive(shared_x)

    @staticmethod
    def _calc_padded_len(unpadded_len: int) -> int:
        if unpadded_len < NIP44_MIN_PLAINTEXT or unpadded_len > NIP44_MAX_PLAINTEXT:
            raise NostrBunkerError("invalid plaintext length")
        if unpadded_len <= 32:
            return 32
        next_power = 1 << math.floor(math.log2(unpadded_len - 1) + 1)
        chunk = 32 if next_power <= 256 else next_power // 8
        return chunk * (((unpadded_len - 1) // chunk) + 1)

    @classmethod
    def _pad_nip44_plaintext(cls, plaintext: str) -> bytes:
        unpadded = plaintext.encode("utf-8")
        unpadded_len = len(unpadded)
        padded_len = cls._calc_padded_len(unpadded_len)
        return unpadded_len.to_bytes(2, "big") + unpadded + (b"\x00" * (padded_len - unpadded_len))

    @classmethod
    def _unpad_nip44_plaintext(cls, padded: bytes) -> str:
        if len(padded) < 2:
            raise NostrBunkerError("invalid padded plaintext")
        unpadded_len = int.from_bytes(padded[:2], "big")
        if unpadded_len < NIP44_MIN_PLAINTEXT:
            raise NostrBunkerError("invalid plaintext length")
        expected_len = 2 + cls._calc_padded_len(unpadded_len)
        if len(padded) != expected_len:
            raise NostrBunkerError("invalid padding size")
        unpadded = padded[2:2 + unpadded_len]
        if len(unpadded) != unpadded_len:
            raise NostrBunkerError("invalid unpadded length")
        if padded[2 + unpadded_len:] != b"\x00" * (len(padded) - 2 - unpadded_len):
            raise NostrBunkerError("invalid padding bytes")
        return unpadded.decode("utf-8")

    @staticmethod
    def _decode_nip44_payload(payload: str) -> tuple[bytes, bytes, bytes]:
        if not payload or payload[0] == "#":
            raise NostrBunkerError("unknown nip44 version")
        if len(payload) < 132 or len(payload) > 87472:
            raise NostrBunkerError("invalid payload size")
        try:
            data = base64.b64decode(payload)
        except Exception as exc:
            raise NostrBunkerError(f"invalid base64 payload: {exc}") from exc
        if len(data) < 99 or len(data) > 65603:
            raise NostrBunkerError("invalid decoded payload size")
        version = data[0]
        if version != NIP44_VERSION:
            raise NostrBunkerError(f"unknown nip44 version {version}")
        nonce = data[1:33]
        ciphertext = data[33:-32]
        mac = data[-32:]
        return nonce, ciphertext, mac

    @staticmethod
    def _hmac_aad(key: bytes, message: bytes, aad: bytes) -> bytes:
        if len(aad) != 32:
            raise NostrBunkerError("nip44 aad must be 32 bytes")
        return hmac.new(key, aad + message, hashlib.sha256).digest()

    @classmethod
    def _get_nip44_message_keys(cls, conversation_key: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
        if len(conversation_key) != 32:
            raise NostrBunkerError("invalid conversation key length")
        if len(nonce) != 32:
            raise NostrBunkerError("invalid nonce length")
        hkdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=76,
            info=nonce,
        )
        keys = hkdf.derive(conversation_key)
        return keys[:32], keys[32:44], keys[44:76]

    @classmethod
    def encrypt_nip44(cls, private_key_hex: str, peer_pubkey_hex: str, plaintext: str) -> str:
        conversation_key = cls.get_nip44_conversation_key(private_key_hex, peer_pubkey_hex)
        nonce = secrets.token_bytes(32)
        chacha_key, chacha_nonce, hmac_key = cls._get_nip44_message_keys(conversation_key, nonce)
        padded = cls._pad_nip44_plaintext(plaintext)
        cipher = Cipher(algorithms.ChaCha20(chacha_key, chacha_nonce), mode=None)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded)
        mac = cls._hmac_aad(hmac_key, ciphertext, nonce)
        return base64.b64encode(bytes([NIP44_VERSION]) + nonce + ciphertext + mac).decode("ascii")

    @classmethod
    def decrypt_nip44(cls, private_key_hex: str, peer_pubkey_hex: str, payload: str) -> str:
        nonce, ciphertext, mac = cls._decode_nip44_payload(payload)
        conversation_key = cls.get_nip44_conversation_key(private_key_hex, peer_pubkey_hex)
        chacha_key, chacha_nonce, hmac_key = cls._get_nip44_message_keys(conversation_key, nonce)
        calculated_mac = cls._hmac_aad(hmac_key, ciphertext, nonce)
        if not hmac.compare_digest(calculated_mac, mac):
            raise NostrBunkerError("invalid MAC")
        cipher = Cipher(algorithms.ChaCha20(chacha_key, chacha_nonce), mode=None)
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext)
        return cls._unpad_nip44_plaintext(padded)
