from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

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

    def connect(self):
        relay = self.settings.get_value(SettingsConstants.SETTING__NOSTR_RELAY_URL)
        if relay.startswith("https://"):
            relay = "wss://" + relay[len("https://"):]
        elif relay.startswith("http://"):
            relay = "ws://" + relay[len("http://"):]
        self.write_status(self.build_status(state=f"connect:{relay}"))
        return relay

    def subscribe(self):
        self.write_status(self.build_status(state="subscribed"))

    def run_once(self):
        if self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER) != SettingsConstants.OPTION__ENABLED:
            self.write_status(self.build_status(state="disabled"))
            return

        relay = self.connect()
        self.subscribe()
        self.write_status(self.build_status(state=f"idle:{relay}"))

    def run_forever(self):
        while True:
            try:
                self.run_once()
            except Exception as exc:
                self.write_status(self.build_status(state="error", last_error=str(exc)))
            time.sleep(30)


def main():
    service = NostrBunkerService()
    if os.environ.get("SEEDSIGNER_NOSTR_RUN_ONCE") == "1":
        service.run_once()
    else:
        service.run_forever()


if __name__ == "__main__":
    main()
