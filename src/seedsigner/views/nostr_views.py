import logging
import subprocess
from pathlib import Path

from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.gui.screens import RET_CODE__BACK_BUTTON, ButtonListScreen
from seedsigner.gui.screens.screen import ButtonOption, KeyboardScreen, QRDisplayScreen
from seedsigner.models.nostr_bunker import NostrSigner
from seedsigner.models.settings_definition import SettingsConstants

from .view import View, Destination, BackStackView, WarningScreen, MainMenuView

logger = logging.getLogger(__name__)


class NostrMenuView(View):
    TOGGLE = ButtonOption("Enable / Disable bunker")
    WIFI = ButtonOption("Configure WiFi")
    SCAN_CONNECT = ButtonOption("Scan Nostr Connect")
    SHOW_CONNECTION = ButtonOption("Show bunker connection")
    EDIT_RELAY = ButtonOption("Edit relay URL")
    TEST_EVENT = ButtonOption("Generate test event")
    SERVICE_STATUS = ButtonOption("Service status")

    def _ensure_bunker_keys(self):
        from pathlib import Path

        priv_path = Path("/tmp/nostr_bunker_private_key.hex")

        if not self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER_PUBKEY):
            kp = NostrSigner.generate()
            self.settings.set_value(SettingsConstants.SETTING__NOSTR_BUNKER_PUBKEY, kp.public_key_hex)
            self.settings.set_value(SettingsConstants.SETTING__NOSTR_BUNKER_SECRET, kp.secret)
            self.controller.nostr_bunker_private_key_hex = kp.private_key_hex
            priv_path.write_text(kp.private_key_hex)
        elif not getattr(self.controller, "nostr_bunker_private_key_hex", None):
            if priv_path.exists():
                self.controller.nostr_bunker_private_key_hex = priv_path.read_text().strip()
            else:
                kp = NostrSigner.generate()
                self.controller.nostr_bunker_private_key_hex = kp.private_key_hex
                priv_path.write_text(kp.private_key_hex)

    def run(self):
        self._ensure_bunker_keys()
        enabled = self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER) == SettingsConstants.OPTION__ENABLED
        status = _("Enabled") if enabled else _("Disabled")
        relay = self.settings.get_value(SettingsConstants.SETTING__NOSTR_RELAY_URL)

        button_data = [
            ButtonOption(f"Bunker mode: {status}"),
            self.WIFI,
            self.SCAN_CONNECT,
            ButtonOption(f"Relay: {relay}"),
            self.SHOW_CONNECTION,
            self.EDIT_RELAY,
            self.TEST_EVENT,
            self.SERVICE_STATUS,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Nostr"),
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(MainMenuView)

        if selected_menu_num == 0:
            new_value = SettingsConstants.OPTION__DISABLED if enabled else SettingsConstants.OPTION__ENABLED
            self.settings.set_value(SettingsConstants.SETTING__NOSTR_BUNKER, new_value)
            return Destination(NostrMenuView, skip_current_view=True)

        if button_data[selected_menu_num] == self.WIFI:
            return Destination(NostrWiFiSSIDEntryView)

        if button_data[selected_menu_num] == self.SCAN_CONNECT:
            from seedsigner.views.scan_views import ScanNostrConnectView
            return Destination(ScanNostrConnectView)

        if button_data[selected_menu_num] == self.SHOW_CONNECTION:
            return Destination(NostrConnectionView)

        if button_data[selected_menu_num] == self.EDIT_RELAY:
            return Destination(NostrRelayEntryView)

        if button_data[selected_menu_num] == self.TEST_EVENT:
            return Destination(NostrTestEventView)

        if button_data[selected_menu_num] == self.SERVICE_STATUS:
            return Destination(NostrServiceStatusView)

        return Destination(BackStackView)


class NostrRelayEntryView(View):
    def run(self):
        value = self.run_screen(
            NostrRelayKeyboardScreen,
            title=_("Relay URL"),
            rows=4,
            cols=10,
            keys_charset="abcdefghijklmnopqrstuvwxyz0123456789:/._-",
            show_save_button=True,
            initial_value=self.settings.get_value(SettingsConstants.SETTING__NOSTR_RELAY_URL),
        )

        if value == RET_CODE__BACK_BUTTON:
            return Destination(NostrMenuView)

        self.settings.set_value(SettingsConstants.SETTING__NOSTR_RELAY_URL, value)
        return Destination(NostrMenuView, clear_history=True)


@dataclass
class NostrRelayKeyboardScreen(KeyboardScreen):
    pass


class NostrWiFiSSIDEntryView(View):
    WIFI_OPTIONS = [
        ("LIVING", "LIVINGBU"),
        ("COWORK", "coworking"),
    ]

    def run(self):
        button_data = [ButtonOption(ssid) for ssid, _password in self.WIFI_OPTIONS]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Configure WiFi"),
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(NostrMenuView)

        ssid, password = self.WIFI_OPTIONS[selected_menu_num]
        return Destination(NostrWiFiConfirmView, view_args={"ssid": ssid, "password": password})


class NostrWiFiConfirmView(View):
    WPA_CONF_PATH = Path("/etc/wpa_supplicant.conf")

    def __init__(self, ssid: str, password: str):
        super().__init__()
        self.ssid = ssid
        self.password = password

    @staticmethod
    def _escape_wpa_value(value: str) -> str:
        return value.replace('\\', '\\\\').replace('"', '\\"')

    def _write_wpa_config(self):
        ssid = self._escape_wpa_value(self.ssid)
        password = self._escape_wpa_value(self.password)
        content = (
            "ctrl_interface=/var/run/wpa_supplicant\n"
            "update_config=0\n"
            "country=US\n"
            "ap_scan=1\n\n"
            "network={\n"
            f'    ssid="{ssid}"\n'
            f'    psk="{password}"\n'
            "    key_mgmt=WPA-PSK\n"
            "    scan_ssid=1\n"
            "    priority=1\n"
            "}\n"
        )
        self.WPA_CONF_PATH.write_text(content)

    def _restart_network(self):
        try:
            subprocess.run(["/etc/init.d/S40network", "restart"], check=False, timeout=30)
        except Exception as exc:
            logger.exception(exc)

    def run(self):
        self._write_wpa_config()
        self._restart_network()

        self.run_screen(
            WarningScreen,
            title=_("WiFi Saved"),
            status_headline=_("Network restart requested"),
            text=f"SSID:\n{self.ssid}\n\nSaved to /etc/wpa_supplicant.conf\n\nIf connection does not come up, reboot and try again.",
            button_data=[ButtonOption("Back")],
            show_back_button=False,
        )
        return Destination(NostrMenuView)


class NostrConnectionView(View):
    def run(self):
        from seedsigner.models.encode_qr import GenericStaticQrEncoder

        pubkey = self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER_PUBKEY)
        secret = self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER_SECRET)
        relay = self.settings.get_value(SettingsConstants.SETTING__NOSTR_RELAY_URL)
        url = NostrSigner.bunker_url(pubkey, relay, secret)

        qr_encoder = GenericStaticQrEncoder(data=url)
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=qr_encoder,
        )
        return Destination(NostrMenuView)


class NostrServiceStatusView(View):
    def run(self):
        enabled = self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER) == SettingsConstants.OPTION__ENABLED
        connect_data = getattr(self.controller, "nostr_connect_data", None) or {}
        relay = connect_data.get("relay") or self.settings.get_value(SettingsConstants.SETTING__NOSTR_RELAY_URL)
        app_pubkey = connect_data.get("pubkey", "not scanned")
        secret = self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER_SECRET) or "missing"
        status = _("Enabled") if enabled else _("Disabled")

        status_path = Path("/tmp/nostr_bunker_service_status.json")
        runtime_status = status_path.read_text() if status_path.exists() else "no runtime status yet"

        self.run_screen(
            WarningScreen,
            title=_("Bunker Service"),
            status_headline=_("Runtime status"),
            text=f"mode: {status}\nrelay: {relay}\napp pubkey: {app_pubkey}\nsecret: {secret}\n\nruntime:\n{runtime_status}",
            button_data=[ButtonOption("Back")],
            show_back_button=False,
        )
        return Destination(NostrMenuView)


class NostrConnectDetailsView(View):
    def run(self):
        data = getattr(self.controller, "nostr_connect_data", None) or {}
        relay = data.get("relay") or self.settings.get_value(SettingsConstants.SETTING__NOSTR_RELAY_URL)
        pubkey = data.get("pubkey", "")
        secret = data.get("secret", "")

        if relay:
            self.settings.set_value(SettingsConstants.SETTING__NOSTR_RELAY_URL, relay)

        self.run_screen(
            WarningScreen,
            title=_("Nostr Connect"),
            status_headline=_("Connection scanned"),
            text=f"pubkey:\n{pubkey}\n\nrelay:\n{relay}\n\nsecret:\n{secret}\n\nBunker service can now use this client connection info.",
            button_data=[ButtonOption("Back")],
            show_back_button=False,
        )
        return Destination(NostrMenuView)


class NostrTestEventView(View):
    def run(self):
        priv = getattr(self.controller, "nostr_bunker_private_key_hex", None)
        if not priv:
            kp = NostrSigner.generate()
            priv = kp.private_key_hex
            self.controller.nostr_bunker_private_key_hex = priv
            self.settings.set_value(SettingsConstants.SETTING__NOSTR_BUNKER_PUBKEY, kp.public_key_hex)
            self.settings.set_value(SettingsConstants.SETTING__NOSTR_BUNKER_SECRET, kp.secret)

        signer = NostrSigner(priv)
        event = signer.sign_event({
            "kind": 1,
            "content": "SeedSigner Nostr bunker test",
            "tags": [],
            "pubkey": self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER_PUBKEY),
        })

        self.run_screen(
            WarningScreen,
            title=_("Test Event"),
            status_headline=_("Signed OK") if signer.verify_event(event) else _("Verification failed"),
            text=f"id:\n{event['id']}\n\nsig:\n{event['sig'][:32]}...",
            button_data=[ButtonOption("Back")],
            show_back_button=False,
        )
        return Destination(NostrMenuView)
