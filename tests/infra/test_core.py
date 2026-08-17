"""Tests for InfraManager subscriber provisioning."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Callable
from unittest import mock

from volte_mutation_fuzzer.infra.core import InfraManager


def _completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _install_fake_run(
    dbctl_results: list | None = None,
    mongo_results: list | None = None,
) -> tuple[Callable, list[list[str]]]:
    """Patch subprocess.run with a docker-exec command router.

    Commands mentioning open5gs-dbctl consume dbctl_results, mongo shell
    invocations consume mongo_results (both default to success). Every
    executed command is recorded for assertions.
    """
    dbctl_results = list(dbctl_results or [])
    mongo_results = list(mongo_results or [])
    calls: list[list[str]] = []

    def run(command, **_kwargs):
        calls.append(command)
        joined = " ".join(command)
        if "open5gs-dbctl" in joined:
            result = dbctl_results.pop(0) if dbctl_results else _completed()
        elif "mongosh" in joined or "mongo" in command:
            result = mongo_results.pop(0) if mongo_results else _completed()
        else:
            result = _completed()
        return result

    return run, calls


def _is_dbctl_command(command: list[str]) -> bool:
    return "open5gs-dbctl" in " ".join(command)


def _is_mongo_command(command: list[str]) -> bool:
    return "mongosh" in " ".join(command) or "mongo" in command


class ProvisionHssSubscriberTests(unittest.TestCase):
    IMSI = "001010000000001"
    KEY = "00112233445566778899AABBCCDDEEFF"
    OPC = "FFEEDDCCBBAA99887766554433221100"
    AMF = "8000"

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "docker-compose.yml").write_text("services: {}\n")
        self.manager = InfraManager(infra_dir=root, env={})

    def _dbctl_calls(self, calls: list[list[str]]) -> list[list[str]]:
        return [c for c in calls if _is_dbctl_command(c)]

    def _mongo_calls(self, calls: list[list[str]]) -> list[list[str]]:
        return [c for c in calls if _is_mongo_command(c)]

    def test_new_subscriber_added_via_dbctl_only(self) -> None:
        run, calls = _install_fake_run(dbctl_results=[_completed()])
        with mock.patch.object(subprocess, "run", side_effect=run):
            self.manager._provision_hss_subscriber(
                imsi=self.IMSI, key=self.KEY, opc=self.OPC, amf=self.AMF
            )
        dbctl_calls = self._dbctl_calls(calls)
        self.assertEqual(len(dbctl_calls), 1)
        self.assertEqual(
            dbctl_calls[0][dbctl_calls[0].index("add") + 1 :],
            [self.IMSI, self.KEY, self.OPC, self.AMF],
        )
        self.assertEqual(self._mongo_calls(calls), [])

    def test_existing_subscriber_credentials_refreshed(self) -> None:
        # Re-provisioning an existing subscriber must refresh the stored
        # credentials: open5gs-dbctl cannot update K/OPC of an existing
        # entry, so the security fields have to be patched via mongosh.
        run, calls = _install_fake_run(
            dbctl_results=[
                _completed(returncode=1, stdout=f"IMSI '{self.IMSI}' already exists\n")
            ],
            mongo_results=[_completed(stdout="credentials-updated\n")],
        )
        with mock.patch.object(subprocess, "run", side_effect=run):
            self.manager._provision_hss_subscriber(
                imsi=self.IMSI, key=self.KEY, opc=self.OPC, amf=self.AMF
            )
        mongo_calls = self._mongo_calls(calls)
        self.assertEqual(len(mongo_calls), 1)
        script = mongo_calls[0][mongo_calls[0].index("--eval") + 1]
        self.assertIn(f'"security.k": "{self.KEY}"', script)
        self.assertIn(f'"security.opc": "{self.OPC}"', script)
        self.assertIn(f'"security.amf": "{self.AMF}"', script)
        # Resetting security.sqn desynchronizes UE/HSS AKA sequence
        # numbers and breaks LTE authentication — it must not be touched.
        self.assertNotIn("sqn", script)
        # The update already handled the existing subscriber; the second
        # dbctl variant (without amf) must not run.
        self.assertEqual(len(self._dbctl_calls(calls)), 1)

    def test_duplicate_key_error_also_refreshes(self) -> None:
        for message in (
            "E11000 duplicate key error collection: open5gs.subscribers",
            "Subscriber Already Exists",
        ):
            with self.subTest(message=message):
                run, calls = _install_fake_run(
                    dbctl_results=[_completed(returncode=1, stdout=message)],
                    mongo_results=[_completed()],
                )
                with mock.patch.object(subprocess, "run", side_effect=run):
                    self.manager._provision_hss_subscriber(
                        imsi=self.IMSI, key=self.KEY, opc=self.OPC, amf=self.AMF
                    )
                self.assertEqual(len(self._mongo_calls(calls)), 1)

    def test_credential_refresh_failure_raises(self) -> None:
        run, _calls = _install_fake_run(
            dbctl_results=[
                _completed(returncode=1, stdout=f"IMSI '{self.IMSI}' already exists")
            ],
            mongo_results=[
                _completed(returncode=1, stderr="MongoServerError: not connected"),
                _completed(returncode=1, stderr="mongo: command not found"),
            ],
        )
        with mock.patch.object(subprocess, "run", side_effect=run):
            with self.assertRaises(RuntimeError) as ctx:
                self.manager._provision_hss_subscriber(
                    imsi=self.IMSI, key=self.KEY, opc=self.OPC, amf=self.AMF
                )
        self.assertIn("failed to update HSS subscriber credentials", str(ctx.exception))
        self.assertIn(self.IMSI, str(ctx.exception))

    def test_dbctl_hard_failure_raises(self) -> None:
        run, _calls = _install_fake_run(
            dbctl_results=[
                _completed(returncode=1, stderr="connection refused"),
                _completed(returncode=1, stderr="connection refused"),
            ]
        )
        with mock.patch.object(subprocess, "run", side_effect=run):
            with self.assertRaises(RuntimeError) as ctx:
                self.manager._provision_hss_subscriber(
                    imsi=self.IMSI, key=self.KEY, opc=self.OPC, amf=self.AMF
                )
        self.assertIn("failed to provision HSS subscriber", str(ctx.exception))


class EnsureImsApnTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "docker-compose.yml").write_text("services: {}\n")
        self.manager = InfraManager(infra_dir=root, env={})

    def test_uses_mongo_shell_with_eval_script(self) -> None:
        run, calls = _install_fake_run(
            mongo_results=[_completed(stdout="ims-apn-added\n")]
        )
        with mock.patch.object(subprocess, "run", side_effect=run):
            self.manager._ensure_ims_apn("001010000000001")
        mongo_calls = [c for c in calls if _is_mongo_command(c)]
        self.assertEqual(len(mongo_calls), 1)
        self.assertIn("--eval", mongo_calls[0])

    def test_failure_raises_runtime_error(self) -> None:
        run, _calls = _install_fake_run(
            mongo_results=[
                _completed(returncode=1, stderr="MongoServerError: boom"),
                _completed(returncode=1, stderr="mongo: command not found"),
            ]
        )
        with mock.patch.object(subprocess, "run", side_effect=run):
            with self.assertRaises(RuntimeError) as ctx:
                self.manager._ensure_ims_apn("001010000000001")
        self.assertIn("failed to update IMS APN", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
