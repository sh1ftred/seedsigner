from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from embit import ec


NIP46_KIND = 24133
CONFIG_PATH = "/tmp/nostr_bunker.json"


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
    def _pkcs7_pad(data: bytes) -> bytes:
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len]) * pad_len

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        if not data:
            raise NostrBunkerError("empty ciphertext")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise NostrBunkerError("invalid padding")
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise NostrBunkerError("invalid padding bytes")
        return data[:-pad_len]

    @staticmethod
    def _shared_secret(private_key_hex: str, peer_pubkey_hex: str) -> bytes:
        return hashlib.sha256(bytes.fromhex(private_key_hex) + bytes.fromhex(peer_pubkey_hex)).digest()

    @classmethod
    def encrypt_nip04(cls, private_key_hex: str, peer_pubkey_hex: str, plaintext: str) -> str:
        key = cls._shared_secret(private_key_hex, peer_pubkey_hex)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(cls._pkcs7_pad(plaintext.encode("utf-8"))) + encryptor.finalize()
        return f"{base64.b64encode(ciphertext).decode()}?iv={base64.b64encode(iv).decode()}"

    @classmethod
    def decrypt_nip04(cls, private_key_hex: str, peer_pubkey_hex: str, payload: str) -> str:
        if "?iv=" not in payload:
            raise NostrBunkerError("missing iv")
        ciphertext_b64, iv_b64 = payload.split("?iv=", 1)
        key = cls._shared_secret(private_key_hex, peer_pubkey_hex)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return cls._pkcs7_unpad(plaintext).decode("utf-8")
