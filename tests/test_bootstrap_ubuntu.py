from pathlib import Path
import subprocess
import unittest


BOOTSTRAP = Path("scripts/bootstrap_ubuntu.sh")


class UbuntuBootstrapScriptTests(unittest.TestCase):
    def test_bootstrap_script_exists_and_has_valid_bash_syntax(self) -> None:
        self.assertTrue(BOOTSTRAP.is_file())

        result = subprocess.run(
            ["bash", "-n", str(BOOTSTRAP)],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_bootstrap_help_is_safe_to_run(self) -> None:
        result = subprocess.run(
            ["bash", str(BOOTSTRAP), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Usage:", result.stdout)
        self.assertIn("--with-host-setup", result.stdout)
        self.assertIn("--build-images", result.stdout)

    def test_bootstrap_covers_real_ue_prerequisites(self) -> None:
        content = BOOTSTRAP.read_text(encoding="utf-8")

        for required_text in (
            "docker.io",
            "docker-compose-v2",
            "docker compose version",
            "sudo is required when not running as root",
            "tshark",
            "tcpdump",
            "/usr/bin/tcpdump",
            "adb",
            "libimobiledevice-utils",
            "usbmuxd",
            "jq",
            "netplan.io",
            "passwd",
            "sudo -v",
            'linux-modules-extra-$(uname -r)',
            "uv python install",
            "uv sync --dev",
            "setup_host.sh --all",
            "poe epc-build",
        ):
            self.assertIn(required_text, content)


if __name__ == "__main__":
    unittest.main()
