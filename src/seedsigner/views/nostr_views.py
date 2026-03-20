import logging
import subprocess
from pathlib import Path

from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.gui.screens import RET_CODE__BACK_BUTTON, ButtonListScreen
from seedsigner.gui.screens.screen import ButtonOption, KeyboardScreen
from seedsigner.models.nostr_bunker import NostrSigner
from seedsigner.models.settings_definition import SettingsConstants

from .view import View, Destination, BackStackView, WarningScreen, MainMenuView

logger = logging.getLogger(__name__)


class NostrMenuView(View):
    TOGGLE = ButtonOption("Enable / Disable bunker")
    WIFI = ButtonOption("Configure WiFi")
    SHOW_CONNECTION = ButtonOption("Show bunker connection")
    EDIT_RELAY = ButtonOption("Edit relay URL")
    TEST_EVENT = ButtonOption("Generate test event")

    def _ensure_bunker_keys(self):
        if not self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER_PUBKEY):
            kp = NostrSigner.generate()
            self.settings.set_value(SettingsConstants.SETTING__NOSTR_BUNKER_PUBKEY, kp.public_key_hex)
            self.settings.set_value(SettingsConstants.SETTING__NOSTR_BUNKER_SECRET, kp.secret)
            # private key is intentionally not persisted in app settings for now
            self.controller.nostr_bunker_private_key_hex = kp.private_key_hex
        elif not getattr(self.controller, "nostr_bunker_private_key_hex", None):
            kp = NostrSigner.generate()
            self.controller.nostr_bunker_private_key_hex = kp.private_key_hex

    def run(self):
        self._ensure_bunker_keys()
        enabled = self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER) == SettingsConstants.OPTION__ENABLED
        status = _("Enabled") if enabled else _("Disabled")
        relay = self.settings.get_value(SettingsConstants.SETTING__NOSTR_RELAY_URL)

        button_data = [
            ButtonOption(f"Bunker mode: {status}"),
            self.WIFI,
            ButtonOption(f"Relay: {relay}"),
            self.SHOW_CONNECTION,
            self.EDIT_RELAY,
            self.TEST_EVENT,
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

        if button_data[selected_menu_num] == self.SHOW_CONNECTION:
            return Destination(NostrConnectionView)

        if button_data[selected_menu_num] == self.EDIT_RELAY:
            return Destination(NostrRelayEntryView)

        if button_data[selected_menu_num] == self.TEST_EVENT:
            return Destination(NostrTestEventView)

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
    def run(self):
        value = self.run_screen(
            NostrWiFiSSIDKeyboardScreen,
            title=_("WiFi SSID"),
            rows=4,
            cols=10,
            keys_charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-",
            show_save_button=True,
        )

        if value == RET_CODE__BACK_BUTTON:
            return Destination(NostrMenuView)

        return Destination(NostrWiFiPasswordEntryView, view_args={"ssid": value})


class NostrWiFiPasswordEntryView(View):
    def __init__(self, ssid: str):
        super().__init__()
        self.ssid = ssid

    def run(self):
        value = self.run_screen(
            NostrWiFiPasswordKeyboardScreen,
            title=_("WiFi Password"),
            rows=4,
            cols=10,
            keys_charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
            show_save_button=True,
        )

        if value == RET_CODE__BACK_BUTTON:
            return Destination(NostrWiFiSSIDEntryView)

        return Destination(NostrWiFiConfirmView, view_args={"ssid": self.ssid, "password": value})


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


@dataclass
class NostrWiFiSSIDKeyboardScreen(KeyboardScreen):
    pass


@dataclass
class NostrWiFiPasswordKeyboardScreen(KeyboardScreen):
    pass


class NostrConnectionView(View):
    def run(self):
        pubkey = self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER_PUBKEY)
        secret = self.settings.get_value(SettingsConstants.SETTING__NOSTR_BUNKER_SECRET)
        relay = self.settings.get_value(SettingsConstants.SETTING__NOSTR_RELAY_URL)
        url = NostrSigner.bunker_url(pubkey, relay, secret)

        self.run_screen(
            WarningScreen,
            title=_("Nostr Connection"),
            status_headline=_("Scan with client"),
            text=f"pubkey:\n{pubkey}\n\nrelay:\n{relay}\n\nsecret:\n{secret}\n\nurl:\n{url}",
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
