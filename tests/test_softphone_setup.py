import subprocess
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from volte_mutation_fuzzer.softphone_setup import (
    BARESIP_DEFAULT_ACCOUNT_URI,
    SoftphoneSetupError,
    detect_platform,
    generate_baresip_accounts,
    generate_baresip_config,
    install_baresip,
    is_baresip_installed,
    main,
    provision_config_dir,
    setup,
)


class GenerateConfigTests(unittest.TestCase):
    def test_generate_baresip_config_contains_sip_listen(self) -> None:
        config = generate_baresip_config(5060)

        self.assertIn("sip_listen", config)
        self.assertIn("0.0.0.0:5060", config)

    def test_generate_baresip_config_custom_port(self) -> None:
        config = generate_baresip_config(5080)

        self.assertIn("0.0.0.0:5080", config)

    def test_generate_baresip_config_disables_audio(self) -> None:
        config = generate_baresip_config()

        self.assertIn("audio_player", config)
        self.assertIn("audio_source", config)
        self.assertIn("audio_alert", config)
        self.assertIn("none", config)

    def test_generate_baresip_accounts_default_uri(self) -> None:
        accounts = generate_baresip_accounts()

        self.assertIn(BARESIP_DEFAULT_ACCOUNT_URI, accounts)

    def test_generate_baresip_accounts_custom_uri(self) -> None:
        custom_uri = "<sip:testuser@192.168.1.1>"
        accounts = generate_baresip_accounts(custom_uri)

        self.assertIn(custom_uri, accounts)


class ProvisionConfigDirTests(unittest.TestCase):
    def test_provision_config_dir_creates_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "baresip-test"

            result = provision_config_dir(config_dir)

            self.assertEqual(result, config_dir)
            self.assertTrue((config_dir / "config").exists())
            self.assertTrue((config_dir / "accounts").exists())

    def test_provision_config_dir_config_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "baresip-test"

            provision_config_dir(config_dir, sip_port=5070)

            config_text = (config_dir / "config").read_text(encoding="utf-8")
            self.assertIn("0.0.0.0:5070", config_text)

    def test_provision_config_dir_accounts_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "baresip-test"

            provision_config_dir(config_dir)

            accounts_text = (config_dir / "accounts").read_text(encoding="utf-8")
            self.assertIn(BARESIP_DEFAULT_ACCOUNT_URI, accounts_text)

    def test_provision_config_dir_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "baresip-test"

            provision_config_dir(config_dir)
            provision_config_dir(config_dir)

            self.assertTrue((config_dir / "config").exists())
            self.assertTrue((config_dir / "accounts").exists())

    def test_provision_config_dir_creates_missing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nested_dir = Path(tmp) / "a" / "b" / "baresip"

            provision_config_dir(nested_dir)

            self.assertTrue(nested_dir.is_dir())


class DetectPlatformTests(unittest.TestCase):
    def test_detect_platform_returns_darwin_on_mac(self) -> None:
        with patch.object(sys, "platform", "darwin"):
            self.assertEqual(detect_platform(), "darwin")

    def test_detect_platform_returns_linux(self) -> None:
        with patch.object(sys, "platform", "linux"):
            self.assertEqual(detect_platform(), "linux")

    def test_detect_platform_raises_on_unsupported(self) -> None:
        with patch.object(sys, "platform", "win32"):
            with self.assertRaises(SoftphoneSetupError):
                detect_platform()


class IsBaresipInstalledTests(unittest.TestCase):
    def test_is_baresip_installed_returns_false_when_missing(self) -> None:
        with patch("volte_mutation_fuzzer.softphone.shutil.which", return_value=None):
            result = is_baresip_installed({})

        self.assertFalse(result)

    def test_is_baresip_installed_returns_true_when_found(self) -> None:
        with patch(
            "volte_mutation_fuzzer.softphone.shutil.which",
            return_value="/usr/bin/baresip",
        ):
            result = is_baresip_installed({})

        self.assertTrue(result)


class InstallBaresipTests(unittest.TestCase):
    def test_install_baresip_calls_brew_on_darwin(self) -> None:
        seen: dict[str, object] = {}

        def fake_runner(
            command: list[str], *, check: bool
        ) -> subprocess.CompletedProcess[str]:
            seen["command"] = command
            return subprocess.CompletedProcess(args=command, returncode=0)

        with patch.object(sys, "platform", "darwin"):
            with patch(
                "volte_mutation_fuzzer.softphone_setup.shutil.which",
                return_value="/opt/homebrew/bin/brew",
            ):
                install_baresip(runner=fake_runner)

        self.assertEqual(
            seen["command"], ["/opt/homebrew/bin/brew", "install", "baresip"]
        )

    def test_install_baresip_calls_apt_on_linux(self) -> None:
        seen: dict[str, object] = {}

        def fake_runner(
            command: list[str], *, check: bool
        ) -> subprocess.CompletedProcess[str]:
            seen["command"] = command
            return subprocess.CompletedProcess(args=command, returncode=0)

        with patch.object(sys, "platform", "linux"):
            with patch(
                "volte_mutation_fuzzer.softphone_setup.shutil.which",
                return_value="/usr/bin/apt-get",
            ):
                install_baresip(runner=fake_runner)

        self.assertEqual(
            seen["command"], ["sudo", "/usr/bin/apt-get", "install", "-y", "baresip"]
        )

    def test_install_baresip_raises_on_nonzero_exit(self) -> None:
        def fake_runner(
            command: list[str], *, check: bool
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=command, returncode=1)

        with patch.object(sys, "platform", "darwin"):
            with patch(
                "volte_mutation_fuzzer.softphone_setup.shutil.which",
                return_value="/opt/homebrew/bin/brew",
            ):
                with self.assertRaises(SoftphoneSetupError):
                    install_baresip(runner=fake_runner)


class SetupTests(unittest.TestCase):
    def test_setup_skips_install_when_already_installed(self) -> None:
        install_called: list[bool] = []

        def fake_runner(
            command: list[str], *, check: bool
        ) -> subprocess.CompletedProcess[str]:
            install_called.append(True)
            return subprocess.CompletedProcess(args=command, returncode=0)

        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "baresip"
            with patch(
                "volte_mutation_fuzzer.softphone_setup.is_baresip_installed",
                return_value=True,
            ):
                setup(install=True, config_dir=config_dir, runner=fake_runner)

        self.assertEqual(install_called, [])

    def test_setup_calls_install_when_missing(self) -> None:
        install_called: list[bool] = []

        def fake_runner(
            command: list[str], *, check: bool
        ) -> subprocess.CompletedProcess[str]:
            install_called.append(True)
            return subprocess.CompletedProcess(args=command, returncode=0)

        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "baresip"
            with patch(
                "volte_mutation_fuzzer.softphone_setup.is_baresip_installed",
                return_value=False,
            ):
                with patch.object(sys, "platform", "darwin"):
                    with patch(
                        "volte_mutation_fuzzer.softphone_setup.shutil.which",
                        return_value="/opt/homebrew/bin/brew",
                    ):
                        setup(install=True, config_dir=config_dir, runner=fake_runner)

        self.assertEqual(install_called, [True])

    def test_setup_returns_provisioned_config_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "baresip"
            with patch(
                "volte_mutation_fuzzer.softphone_setup.is_baresip_installed",
                return_value=True,
            ):
                result = setup(install=True, config_dir=config_dir)

            self.assertEqual(result, config_dir)
            self.assertTrue((config_dir / "config").exists())
            self.assertTrue((config_dir / "accounts").exists())


class MainTests(unittest.TestCase):
    def test_main_prints_config_dir_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "baresip"
            stdout = StringIO()
            with patch(
                "volte_mutation_fuzzer.softphone_setup.is_baresip_installed",
                return_value=True,
            ):
                with patch(
                    "volte_mutation_fuzzer.softphone_setup.setup",
                    return_value=config_dir,
                ):
                    import contextlib

                    with contextlib.redirect_stdout(stdout):
                        main()

        self.assertIn(str(config_dir), stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
