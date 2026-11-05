#!/usr/bin/env python3
import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("firewall-web-config.py")
SPEC = importlib.util.spec_from_file_location("firewall_web_config", MODULE_PATH)
config = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(config)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.environment = self.root / "firewall-web.env"
        self.pin_file = self.root / "initial-pin"

    def tearDown(self):
        self.temp.cleanup()

    def apply(self, mode, answers):
        with contextlib.redirect_stdout(io.StringIO()):
            config.apply_config(self.environment, mode, answers, self.pin_file)

    @staticmethod
    def answers(host="127.0.0.1", port="5005", pin="", backend="auto", ack=""):
        return [host, port, pin, backend, ack]

    def test_initial_install_generates_four_digit_pin_with_leading_zeroes(self):
        with mock.patch.object(config.secrets, "randbelow", return_value=7):
            self.apply("initial", self.answers("0.0.0.0", "5006"))
        values = config.read_config(self.environment)
        self.assertEqual(values["NFT_SECRET"], "0007")
        self.assertEqual(values["NFT_HOST"], "0.0.0.0")
        self.assertEqual(values["NFT_PORT"], "5006")
        self.assertEqual(self.pin_file.read_text().strip(), "0007")
        self.assertEqual(self.environment.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.pin_file.stat().st_mode & 0o777, 0o600)

    def test_existing_administrator_values_and_unrelated_entries_survive_initial_setup(self):
        self.environment.write_text(
            "NFT_SECRET=0123\nNFT_HOST=192.0.2.10\nNFT_PORT=5443\n"
            "NFT_BACKEND=ufw\nNFT_BACKEND_ACK=\nCUSTOM_SETTING=keep-me\n"
        )
        self.apply("initial", self.answers("127.0.0.1", "5005", "", "auto"))
        values = config.read_config(self.environment)
        self.assertEqual(values["NFT_SECRET"], "0123")
        self.assertEqual(values["NFT_HOST"], "192.0.2.10")
        self.assertEqual(values["NFT_PORT"], "5443")
        self.assertEqual(values["NFT_BACKEND"], "ufw")
        self.assertEqual(values["CUSTOM_SETTING"], "keep-me")
        self.assertFalse(self.pin_file.exists())

    def test_reconfiguration_uses_supplied_values_and_rotates_blank_pin(self):
        self.environment.write_text(
            "NFT_SECRET=0123\nNFT_HOST=192.0.2.10\nNFT_PORT=5443\n"
            "NFT_BACKEND=auto\nNFT_BACKEND_ACK=\nCUSTOM_SETTING=keep-me\n"
        )
        with mock.patch.object(config.secrets, "randbelow", return_value=42):
            self.apply("reconfigure", self.answers("127.0.0.1", "5006", "", "inspection"))
        values = config.read_config(self.environment)
        self.assertEqual(values["NFT_SECRET"], "0042")
        self.assertEqual(values["NFT_HOST"], "127.0.0.1")
        self.assertEqual(values["NFT_PORT"], "5006")
        self.assertEqual(values["NFT_BACKEND"], "inspection")
        self.assertEqual(values["CUSTOM_SETTING"], "keep-me")

    def test_upgrade_update_preserves_pin_and_only_changes_explicit_settings(self):
        self.environment.write_text(
            "NFT_SECRET=0099\nNFT_HOST=127.0.0.1\nNFT_PORT=5005\n"
            "NFT_BACKEND=auto\nNFT_BACKEND_ACK=\nCUSTOM_SETTING=retained\n"
        )
        self.apply("update", self.answers("", "", "", "inspection"))
        values = config.read_config(self.environment)
        self.assertEqual(values["NFT_SECRET"], "0099")
        self.assertEqual(values["NFT_BACKEND"], "inspection")
        self.assertEqual(values["CUSTOM_SETTING"], "retained")

    def test_invalid_values_do_not_modify_the_file(self):
        original = "NFT_SECRET=1234\nNFT_HOST=127.0.0.1\nNFT_PORT=5005\nNFT_BACKEND=auto\n"
        self.environment.write_text(original)
        with self.assertRaises(config.ConfigError):
            self.apply("update", self.answers("", "70000", "", ""))
        self.assertEqual(self.environment.read_text(), original)

    def test_environment_file_is_parsed_as_data_not_executed(self):
        marker = self.root / "should-not-exist"
        self.environment.write_text(
            'NFT_SECRET=1234\nNFT_HOST=127.0.0.1\nNFT_PORT=5005\n'
            'NFT_BACKEND=auto\nNFT_ALLOWED_ORIGINS="$(touch '
            + str(marker)
            + ')"\n'
        )
        result = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "exec",
                "--config",
                str(self.environment),
                "--",
                sys.executable,
                "-c",
                'import os; print(os.environ["NFT_ALLOWED_ORIGINS"])',
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("touch", result.stdout)
        self.assertFalse(marker.exists())

    def test_invalid_numeric_address_is_rejected(self):
        with self.assertRaises(config.ConfigError):
            config.validate_host("999.999.999.999")

    def test_symlink_configuration_is_rejected(self):
        target = self.root / "target"
        target.write_text("NFT_SECRET=1234\n")
        self.environment.symlink_to(target)
        with self.assertRaises(config.ConfigError):
            config.read_config(self.environment)


if __name__ == "__main__":
    unittest.main()
