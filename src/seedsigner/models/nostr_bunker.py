from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

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
        return f"nostrconnect://{bunker_pubkey_hex}?relay={relay_url}&secret={secret}"

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
