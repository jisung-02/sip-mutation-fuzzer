from io import StringIO
from pathlib import Path
import contextlib
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from volte_mutation_fuzzer.softphone import (
    SoftphoneConfigError,
    build_baresip_command,
    main,
    resolve_baresip_binary,
    resolve_baresip_config_dir,
    run_baresip,
)


class SoftphoneRunnerTests(unittest.TestCase):
    def test_build_baresip_command_uses_env_and_extra_args(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "baresip"
            binary_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary_path.chmod(0o755)

            command = build_baresip_command(
                {
                    "VMF_SOFTPHONE_BIN": str(binary_path),
                    "VMF_SOFTPHONE_CONFIG_DIR": temp_dir,
                    "VMF_SOFTPHONE_ARGS": "-v -e /dial 100",
                }
            )

        self.assertEqual(
            command,
            [
                str(binary_path),
                "-f",
                temp_dir,
                "-v",
                "-e",
                "/dial",
                "100",
            ],
        )

    def test_resolve_baresip_binary_falls_back_to_path_lookup(self) -> None:
        with patch(
            "volte_mutation_fuzzer.softphone.shutil.which",
            return_value="/usr/bin/baresip",
        ):
            resolved = resolve_baresip_binary({})

        self.assertEqual(resolved, "/usr/bin/baresip")

    def test_resolve_baresip_binary_raises_when_configured_binary_is_missing(
        self,
    ) -> None:
        with patch("volte_mutation_fuzzer.softphone.shutil.which", return_value=None):
            with self.assertRaises(SoftphoneConfigError):
                resolve_baresip_binary({"VMF_SOFTPHONE_BIN": "baresip-dev"})

    def test_resolve_baresip_config_dir_requires_existing_directory(self) -> None:
        missing_dir = Path("/tmp/vmf-softphone-missing")

        with self.assertRaises(SoftphoneConfigError):
            resolve_baresip_config_dir({"VMF_SOFTPHONE_CONFIG_DIR": str(missing_dir)})

    def test_run_baresip_invokes_runner_with_expected_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "baresip"
            binary_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary_path.chmod(0o755)
            seen: dict[str, object] = {}

            def fake_runner(
                command: list[str], *, check: bool
            ) -> subprocess.CompletedProcess[str]:
                seen["command"] = command
                seen["check"] = check
                return subprocess.CompletedProcess(args=command, returncode=7)

            return_code = run_baresip(
                {
                    "VMF_SOFTPHONE_BIN": str(binary_path),
                    "VMF_SOFTPHONE_CONFIG_DIR": temp_dir,
                },
                runner=fake_runner,
            )

        self.assertEqual(return_code, 7)
        self.assertEqual(
            seen["command"],
            [str(binary_path), "-f", temp_dir],
        )
        self.assertFalse(seen["check"])

    def test_main_prints_clear_error_for_missing_config_dir(self) -> None:
        stderr = StringIO()

        with patch(
            "volte_mutation_fuzzer.softphone.shutil.which",
            return_value="/usr/bin/baresip",
        ):
            with patch(
                "volte_mutation_fuzzer.softphone._DEFAULT_BARESIP_CONFIG_DIR",
                Path("/nonexistent/baresip-config-dir"),
            ):
                with patch.dict(os.environ, {}, clear=True):
                    with contextlib.redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as caught:
                            main()

        self.assertEqual(caught.exception.code, 2)
        self.assertIn("poe softphone-setup", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
