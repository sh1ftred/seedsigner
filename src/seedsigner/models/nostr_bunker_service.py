from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path

from seedsigner.models.nostr_bunker import NIP46_KIND
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants


STATUS_PATH = Path("/tmp/nostr_bunker_service_status.json")


@dataclass
class BunkerServiceStatus:
    enabled: bool
    relay: str
    state: str
    app_pubkey: str = ""
    last_error: str = ""
    updated_at: int = 0


class NostrBunkerService:
    def __init__(self):
        self.settings = Settings.get_instance()
        self.ws = None

    def build_status(self, state: str, last_error: str = "") -> BunkerServiceStatus:
        connect_data = getattr(self, "connect_data", {}) or {}
        return BunkerServiceStatus(
            enabled=self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER) == SettingsConstants.OPTION__ENABLED,
            relay=self.settings.get_value(SettingsConstants.SETTING__NOSTR_RELAY_URL),
            state=state,
            app_pubkey=connect_data.get("pubkey", ""),
            last_error=last_error,
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
            content = event.get("content", "") if isinstance(event, dict) else ""
            self.write_status(self.build_status(state=f"event:{content[:32]}"))
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

        await self.connect()
        await self.subscribe()

        while True:
            raw = await asyncio.wait_for(self.ws.recv(), timeout=60)
            await self.handle_message(raw)

    async def run_forever_async(self):
        while True:
            try:
                await self.run_once()
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
