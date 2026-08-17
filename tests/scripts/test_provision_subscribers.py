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


class ProvisionPyhssTests(unittest.TestCase):
    def _subscribers(self) -> list[dict]:
        return [
            {
                "imsi": "001010000000001",
                "ki": "00112233445566778899AABBCCDDEEFF",
                "opc": "FFEEDDCCBBAA99887766554433221100",
                "msisdn": "222222",
            }
        ]

    def test_success_flow_resolves_auc_id_from_upsert_response(self) -> None:
        put_results = [
            (200, b"{}"),  # apn internet
            (200, b"{}"),  # apn ims
            (200, b'{"auc_id": 7}'),  # auc
            (200, b"{}"),  # subscriber
            (200, b"{}"),  # ims_subscriber
        ]
        with (
            mock.patch.object(
                provision_subscribers_script,
                "put_json",
                side_effect=put_results,
            ) as put_mock,
            mock.patch.object(
                provision_subscribers_script, "get_json", return_value=(0, b"")
            ) as get_mock,
        ):
            with _capture_stdout() as stdout:
                provision_subscribers_script.provision_pyhss({}, self._subscribers())
        self.assertEqual(put_mock.call_count, 5)
        self.assertEqual(get_mock.call_count, 0)
        subscriber_payload = put_mock.call_args_list[3].args[1]
        self.assertEqual(subscriber_payload["auc_id"], 7)
        self.assertIn("Done", stdout.getvalue())

    def test_unreachable_pyhss_exits_nonzero(self) -> None:
        # The upsert statuses used to be discarded entirely: with PyHSS
        # down the script still printed "APNs ready"/"Complete!".
        with (
            mock.patch.object(
                provision_subscribers_script,
                "put_json",
                return_value=(0, b""),
            ),
            mock.patch.object(
                provision_subscribers_script, "get_json", return_value=(0, b"")
            ),
        ):
            with _capture_stdout() as stdout:
                with self.assertRaises(SystemExit) as ctx:
                    provision_subscribers_script.provision_pyhss(
                        {}, self._subscribers()
                    )
        self.assertEqual(ctx.exception.code, 1)
        output = stdout.getvalue()
        self.assertIn("apn:internet", output)
        self.assertIn("PyHSS provisioning failed", output)
        self.assertNotIn("Done", output)

    def test_unresolved_auc_id_exits_without_subscriber_write(self) -> None:
        # The old code fell back to the loop index as auc_id, silently
        # writing a wrong reference into the subscriber row.
        put_results = [
            (200, b"{}"),  # apn internet
            (200, b"{}"),  # apn ims
            (200, b"{}"),  # auc upsert "succeeded" but exposes no id
        ]
        with (
            mock.patch.object(
                provision_subscribers_script,
                "put_json",
                side_effect=put_results,
            ) as put_mock,
            mock.patch.object(
                provision_subscribers_script,
                "get_json",
                return_value=(200, b"{}"),
            ) as get_mock,
        ):
            with _capture_stdout() as stdout:
                with self.assertRaises(SystemExit) as ctx:
                    provision_subscribers_script.provision_pyhss(
                        {}, self._subscribers()
                    )
        self.assertEqual(ctx.exception.code, 1)
        self.assertEqual(put_mock.call_count, 3)
        self.assertEqual(get_mock.call_count, 1)
        self.assertIn("auc_id", stdout.getvalue())


class CheckEpcRunningTests(unittest.TestCase):
    def _run_with_containers(self, names: str) -> bool:
        result = mock.MagicMock()
        result.stdout = names
        with mock.patch.object(
            provision_subscribers_script.subprocess, "run", return_value=result
        ):
            return provision_subscribers_script.check_epc_running()

    def test_all_required_containers_running(self) -> None:
        self.assertTrue(self._run_with_containers("hss\nmongo\npyhss\n"))

    def test_missing_containers_fail_check(self) -> None:
        # Only checking "hss" let provisioning start with mongo/pyhss down
        # and fail halfway through.
        with _capture_stdout() as stdout:
            result = self._run_with_containers("hss\n")
        self.assertFalse(result)
        self.assertIn("mongo", stdout.getvalue())
        self.assertIn("pyhss", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
