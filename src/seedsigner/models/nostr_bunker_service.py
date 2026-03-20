from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from dataclasses import dataclass, asdict
from pathlib import Path

from seedsigner.models.nostr_bunker import NIP46_KIND, NostrSigner
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants


STATUS_PATH = Path("/tmp/nostr_bunker_service_status.json")
PRIVATE_KEY_PATH = Path("/tmp/nostr_bunker_private_key.hex")
NOSTR_CONNECT_PATH = Path("/tmp/nostr_connect.json")


@dataclass
class BunkerServiceStatus:
    enabled: bool
    relay: str
    state: str
    app_pubkey: str = ""
    last_error: str = ""
    last_request_id: str = ""
    last_method: str = ""
    updated_at: int = 0


class NostrBunkerService:
    def __init__(self):
        self.settings = Settings.get_instance()
        self.ws = None
        self.connect_data = self.load_connect_data()
        self.private_key_hex = self.load_private_key_hex()
        self.signer = NostrSigner(self.private_key_hex) if self.private_key_hex else None

    def load_connect_data(self) -> dict:
        if NOSTR_CONNECT_PATH.exists():
            try:
                return json.loads(NOSTR_CONNECT_PATH.read_text())
            except Exception:
                return {}
        return {}

    def load_private_key_hex(self) -> str:
        if PRIVATE_KEY_PATH.exists():
            return PRIVATE_KEY_PATH.read_text().strip()
        return ""

    def build_status(self, state: str, last_error: str = "", last_request_id: str = "", last_method: str = "") -> BunkerServiceStatus:
        connect_data = self.connect_data or {}
        return BunkerServiceStatus(
            enabled=self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER) == SettingsConstants.OPTION__ENABLED,
            relay=self.settings.get_value(SettingsConstants.SETTING__NOSTR_RELAY_URL),
            state=state,
            app_pubkey=connect_data.get("pubkey", ""),
            last_error=last_error,
            last_request_id=last_request_id,
            last_method=last_method,
            updated_at=int(time.time()),
        )

    def write_status(self, status: BunkerServiceStatus):
        STATUS_PATH.write_text(json.dumps(asdict(status), separators=(",", ":")))

    def relay_to_websocket_url(self, relay: str) -> str:
        if relay.startswith("https://"):
            return "wss://" + relay[len("https://"):]
        if relay.startswith("http://"):
            return "ws://" + relay[len("http://"):]
        return relay

    async def connect(self):
        import websockets

        relay = self.settings.get_value(SettingsConstants.SETTING__NOSTR_RELAY_URL)
        ws_url = self.relay_to_websocket_url(relay)
        self.write_status(self.build_status(state=f"connect:{ws_url}"))
        self.ws = await websockets.connect(ws_url, open_timeout=20, ping_interval=20, ping_timeout=20)
        self.write_status(self.build_status(state=f"connected:{ws_url}"))
        return ws_url

    async def subscribe(self):
        pubkey = self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER_PUBKEY)
        filters = {
            "kinds": [NIP46_KIND],
            "#p": [pubkey],
            "limit": 20,
        }
        req = ["REQ", "seedsigner-bunker", filters]
        await self.ws.send(json.dumps(req, separators=(",", ":")))
        self.write_status(self.build_status(state="subscribed"))

    def parse_request_event(self, event: dict) -> tuple[str, str, list]:
        content = event.get("content", "")
        payload = json.loads(content)
        if not isinstance(payload, dict):
            raise ValueError("request content must be a JSON object")
        request_id = payload.get("id", "")
        method = payload.get("method", "")
        params = payload.get("params", [])
        if not isinstance(params, list):
            raise ValueError("params must be a list")
        return request_id, method, params

    def build_response_content(self, request_id: str, result=None, error: str | None = None) -> str:
        payload = {"id": request_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result
        return json.dumps(payload, separators=(",", ":"))

    def get_public_key(self) -> str:
        if not self.signer:
            raise RuntimeError("missing bunker private key")
        return self.signer.public_key_hex

    def handle_request(self, method: str, params: list):
        if method == "connect":
            remote_pubkey = params[0] if params else ""
            expected_secret = self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER_SECRET)
            supplied_secret = params[1] if len(params) > 1 else ""
            if expected_secret and supplied_secret != expected_secret:
                raise ValueError("invalid bunker secret")
            return {"pubkey": self.get_public_key(), "remote_pubkey": remote_pubkey}

        if method == "get_public_key":
            return self.get_public_key()

        if method == "ping":
            return "pong"

        if method == "sign_event":
            if not params:
                raise ValueError("missing event parameter")
            event = json.loads(params[0]) if isinstance(params[0], str) else params[0]
            if not isinstance(event, dict):
                raise ValueError("event must be an object")
            signed = self.signer.sign_event(event)
            return json.dumps(signed, separators=(",", ":"))

        raise ValueError(f"unsupported method: {method}")

    async def publish_response(self, client_pubkey: str, request_id: str, method: str, result=None, error: str | None = None):
        if not self.signer:
            raise RuntimeError("missing bunker signer")
        content = self.build_response_content(request_id=request_id, result=result, error=error)
        event = self.signer.make_signed_nip46_event(client_pubkey_hex=client_pubkey, content=content)
        await self.ws.send(json.dumps(["EVENT", event], separators=(",", ":")))
        self.write_status(self.build_status(
            state="response-sent" if error is None else "response-error-sent",
            last_error=error or "",
            last_request_id=request_id,
            last_method=method,
        ))

    async def process_event(self, event: dict):
        if not isinstance(event, dict):
            return
        client_pubkey = event.get("pubkey", "")
        request_id = ""
        method = ""
        try:
            request_id, method, params = self.parse_request_event(event)
            result = self.handle_request(method, params)
            await self.publish_response(client_pubkey=client_pubkey, request_id=request_id, method=method, result=result)
        except Exception as exc:
            rid = request_id or secrets.token_hex(8)
            await self.publish_response(client_pubkey=client_pubkey, request_id=rid, method=method or "unknown", error=str(exc))

    async def handle_message(self, raw: str):
        try:
            msg = json.loads(raw)
        except Exception:
            self.write_status(self.build_status(state="message-invalid", last_error="invalid json from relay"))
            return

        if not isinstance(msg, list) or len(msg) < 2:
            self.write_status(self.build_status(state="message-invalid", last_error="unexpected relay message"))
            return

        msg_type = msg[0]
        if msg_type == "EVENT" and len(msg) >= 3:
            event = msg[2]
            self.write_status(self.build_status(state="request-received"))
            await self.process_event(event)
            return

        if msg_type == "NOTICE":
            notice = msg[1] if len(msg) > 1 else ""
            self.write_status(self.build_status(state="notice", last_error=str(notice)))
            return

        if msg_type == "EOSE":
            self.write_status(self.build_status(state="eose"))
            return

        self.write_status(self.build_status(state=f"message:{msg_type}"))

    async def run_once(self):
        if self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER) != SettingsConstants.OPTION__ENABLED:
            self.write_status(self.build_status(state="disabled"))
            return
        if not self.signer:
            self.write_status(self.build_status(state="error", last_error="missing bunker private key"))
            return

        await self.connect()
        await self.subscribe()

        while True:
            raw = await asyncio.wait_for(self.ws.recv(), timeout=60)
            await self.handle_message(raw)

    async def run_forever_async(self):
        while True:
            try:
                self.run_once_task = self.run_once()
                await self.run_once_task
            except Exception as exc:
                self.write_status(self.build_status(state="error", last_error=str(exc)))
                await asyncio.sleep(10)
            finally:
                if self.ws is not None:
                    try:
                        await self.ws.close()
                    except Exception:
                        pass
                    self.ws = None

    def run_forever(self):
        asyncio.run(self.run_forever_async())


def main():
    service = NostrBunkerService()
    if os.environ.get("SEEDSIGNER_NOSTR_RUN_ONCE") == "1":
        asyncio.run(service.run_once())
    else:
        service.run_forever()


if __name__ == "__main__":
    main()
