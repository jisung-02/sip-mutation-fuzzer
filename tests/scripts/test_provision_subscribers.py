"""Tests for the scripts/provision_subscribers.py CLI wrapper."""

from __future__ import annotations

import importlib.util
import io
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from typing import Iterator
from unittest import mock

_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "provision_subscribers.py"
)


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "provision_subscribers_script", _SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provision_subscribers_script = _load_script()


@contextmanager
def _capture_stdout() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        yield buffer


class ProvisionOpen5gsTests(unittest.TestCase):
    def _subscribers(self) -> list[dict]:
        return [
            {
                "imsi": "001010000000001",
                "ki": "00112233445566778899AABBCCDDEEFF",
                "opc": "FFEEDDCCBBAA99887766554433221100",
                "msisdn": "222222",
            }
        ]

    def test_success_reports_status_and_continues(self) -> None:
        with mock.patch.object(
            provision_subscribers_script,
            "docker_exec",
            return_value=(0, "inserted\n", ""),
        ) as exec_mock:
            with _capture_stdout() as stdout:
                provision_subscribers_script.provision_open5gs({}, self._subscribers())
        self.assertIn("inserted", stdout.getvalue())
        self.assertIn("Done", stdout.getvalue())
        command = exec_mock.call_args.args
        self.assertEqual(
            command[:5], ("mongo", "mongosh", "open5gs", "--quiet", "--eval")
        )
        # The mongosh script must embed the subscriber credentials.
        self.assertIn("00112233445566778899AABBCCDDEEFF", command[5])
        self.assertIn("001010000000001", command[5])

    def test_mongosh_failure_exits_before_pyhss(self) -> None:
        # The mongosh result used to be discarded: a failed run still
        # printed "Done" and provisioning continued to PyHSS with a
        # half-provisioned Open5GS and a false success report.
        with mock.patch.object(
            provision_subscribers_script,
            "docker_exec",
            return_value=(1, "", "MongoNetworkError: connection refused"),
        ):
            with _capture_stdout() as stdout:
                with self.assertRaises(SystemExit) as ctx:
                    provision_subscribers_script.provision_open5gs(
                        {}, self._subscribers()
                    )
        self.assertEqual(ctx.exception.code, 1)
        output = stdout.getvalue()
        self.assertIn("MongoNetworkError: connection refused", output)
        self.assertIn("001010000000001", output)
        self.assertNotIn("Done", output)

    def test_missing_sentinel_output_counts_as_failure(self) -> None:
        # rc == 0 but neither "inserted" nor "updated" printed: the script
        # did not actually provision the subscriber.
        with mock.patch.object(
            provision_subscribers_script,
            "docker_exec",
            return_value=(0, "", ""),
        ):
            with _capture_stdout() as stdout:
                with self.assertRaises(SystemExit):
                    provision_subscribers_script.provision_open5gs(
                        {}, self._subscribers()
                    )
        self.assertIn("mongosh exited with status 0", stdout.getvalue())

    def test_all_subscribers_attempted_before_exit(self) -> None:
        subscribers = self._subscribers() + [
            {
                "imsi": "001010000000002",
                "ki": "AA" * 16,
                "opc": "BB" * 16,
                "msisdn": "222223",
            }
        ]
        results = [(1, "", "boom"), (0, "updated\n", "")]
        with mock.patch.object(
            provision_subscribers_script,
            "docker_exec",
            side_effect=results,
        ) as exec_mock:
            with _capture_stdout() as stdout:
                with self.assertRaises(SystemExit):
                    provision_subscribers_script.provision_open5gs({}, subscribers)
        self.assertEqual(exec_mock.call_count, 2)
        output = stdout.getvalue()
        self.assertIn("001010000000001", output)
        self.assertIn("001010000000002", output)
        self.assertIn("updated", output)


if __name__ == "__main__":
    unittest.main()
