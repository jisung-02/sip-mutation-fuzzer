"""Tests for InfraManager subscriber provisioning."""

from __future__ import annotations

import email.message
import io
import json
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable
from unittest import mock
from urllib.parse import urlparse

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


def _urlopen_ok(status: int = 200, body: str = "{}"):
    payload = mock.MagicMock()
    payload.status = status
    payload.read.return_value = body.encode("utf-8")
    handle = mock.MagicMock()
    handle.__enter__.return_value = payload
    return handle


def _http_error(status: int, body: str = "") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "http://localhost:8080",
        status,
        "error",
        email.message.Message(),
        io.BytesIO(body.encode()),
    )


class _PyhssRouter:
    """Route urllib.request.urlopen calls to canned PyHSS responses.

    Handlers are matched on (method, URL path) so "/subscriber/" never
    collides with "/ims_subscriber/". Each registered handler fires once,
    in registration order; unmatched requests succeed with an empty body.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bytes | None]] = []
        self._routes: dict[tuple[str, str], list] = {}

    def add(
        self,
        method: str,
        path: str,
        *,
        status: int = 200,
        body: str = "{}",
        error: Exception | None = None,
    ) -> None:
        handler = error if error is not None else _urlopen_ok(status, body)
        self._routes.setdefault((method, path), []).append(handler)

    def __call__(self, request, timeout=None):  # noqa: ANN001
        method = request.get_method()
        path = urlparse(request.full_url).path
        self.calls.append((method, path, request.data))
        handlers = self._routes.get((method, path))
        if handlers:
            handler = handlers.pop(0)
            if isinstance(handler, Exception):
                raise handler
            return handler
        return _urlopen_ok(200, "{}")

    def sent_payloads(self, method: str, path: str) -> list[dict]:
        return [
            json.loads(data)
            for m, p, data in self.calls
            if m == method and p == path and data is not None
        ]

    def request_paths(self) -> list[tuple[str, str]]:
        return [(method, path) for method, path, _data in self.calls]


class InfraManagerTestCase(unittest.TestCase):
    def make_manager(self) -> InfraManager:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "docker-compose.yml").write_text("services: {}\n")
        return InfraManager(infra_dir=root, env={})


class ProvisionHssSubscriberTests(InfraManagerTestCase):
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

    def test_ims_apn_session_matches_provisioning_script(self) -> None:
        # infra must produce the same IMS APN session data as
        # scripts/provision_subscribers.py (type 1 = IPv4, IMS signalling
        # ARP priority 1): diverging here silently rewrote subscriber data
        # depending on which provisioner ran last.
        run, calls = _install_fake_run(
            mongo_results=[_completed(stdout="ims-apn-added\n")]
        )
        with mock.patch.object(subprocess, "run", side_effect=run):
            self.manager._ensure_ims_apn("001010000000001")
        script = next(
            command[command.index("--eval") + 1]
            for command in calls
            if _is_mongo_command(command)
        )
        self.assertIn("type: 1", script)
        self.assertIn("priority_level: 1", script)
        self.assertNotIn("type: 3", script)
        self.assertNotIn("priority_level: 8", script)


class ProvisionPyhssSubscriberTests(InfraManagerTestCase):
    IMSI = "001010000000001"
    MSISDN = "222222"
    KEY = "00112233445566778899AABBCCDDEEFF"
    OPC = "FFEEDDCCBBAA99887766554433221100"
    AMF = "8000"

    def setUp(self) -> None:
        self.manager = self.make_manager()

    def _provision(self, router: _PyhssRouter) -> None:
        with mock.patch.object(urllib.request, "urlopen", side_effect=router):
            self.manager._provision_pyhss_subscriber(
                imsi=self.IMSI,
                msisdn=self.MSISDN,
                key=self.KEY,
                opc=self.OPC,
                amf=self.AMF,
            )

    def _add_success_routes(self, router: _PyhssRouter) -> None:
        router.add("PUT", "/auc/", body=json.dumps({"auc_id": 7}))
        router.add("PUT", "/subscriber/")
        router.add("PUT", "/ims_subscriber/")

    def test_fresh_subscriber_creates_all_three_rows(self) -> None:
        router = _PyhssRouter()
        self._add_success_routes(router)
        self._provision(router)
        paths = router.request_paths()
        self.assertIn(("PUT", "/auc/"), paths)
        self.assertIn(("PUT", "/subscriber/"), paths)
        self.assertIn(("PUT", "/ims_subscriber/"), paths)

        auc_payload = router.sent_payloads("PUT", "/auc/")[0]
        self.assertEqual(auc_payload["ki"], self.KEY)
        self.assertEqual(auc_payload["opc"], self.OPC)
        self.assertEqual(auc_payload["amf"], self.AMF)
        self.assertEqual(auc_payload["imsi"], self.IMSI)

        subscriber_payload = router.sent_payloads("PUT", "/subscriber/")[0]
        self.assertEqual(subscriber_payload["auc_id"], 7)
        self.assertTrue(subscriber_payload["enabled"])
        self.assertEqual(subscriber_payload["msisdn"], self.MSISDN)

    def test_ims_subscriber_payload_includes_required_ifc_path(self) -> None:
        # ifc_path is mandatory: null makes the S-CSCF answer the MAR with
        # 403, so REGISTER never completes.
        router = _PyhssRouter()
        self._add_success_routes(router)
        self._provision(router)
        payload = router.sent_payloads("PUT", "/ims_subscriber/")[0]
        self.assertEqual(payload["ifc_path"], "default_ifc.xml")
        self.assertEqual(
            payload["scscf"],
            "sip:scscf.ims.mnc001.mcc001.3gppnetwork.org:6060",
        )
        self.assertEqual(payload["scscf_realm"], "ims.mnc001.mcc001.3gppnetwork.org")
        self.assertEqual(
            payload["scscf_peer"], "scscf.ims.mnc001.mcc001.3gppnetwork.org"
        )

    def test_existing_rows_are_patched_and_auc_sqn_preserved(self) -> None:
        router = _PyhssRouter()
        router.add("PUT", "/auc/", error=_http_error(409, "duplicate"))
        router.add("GET", f"/auc/imsi/{self.IMSI}", body=json.dumps({"auc_id": 7}))
        router.add("PATCH", "/auc/7", body=json.dumps({"auc_id": 7}))
        router.add("PUT", "/subscriber/", error=_http_error(409, "duplicate"))
        router.add(
            "GET",
            f"/subscriber/imsi/{self.IMSI}",
            body=json.dumps({"subscriber_id": 3}),
        )
        router.add("PATCH", "/subscriber/3")
        router.add("PUT", "/ims_subscriber/", error=_http_error(409, "duplicate"))
        router.add(
            "GET",
            f"/ims_subscriber/imsi/{self.IMSI}",
            body=json.dumps({"ims_subscriber_id": 5}),
        )
        router.add("PATCH", "/ims_subscriber/5")
        self._provision(router)

        auc_patch = router.sent_payloads("PATCH", "/auc/7")[0]
        self.assertEqual(auc_patch["ki"], self.KEY)
        self.assertEqual(auc_patch["opc"], self.OPC)
        # Resetting sqn desynchronizes the IMS AKA sequence number shared
        # with the UE — the PATCH payload must not contain it.
        self.assertNotIn("sqn", auc_patch)

        ims_patch = router.sent_payloads("PATCH", "/ims_subscriber/5")[0]
        self.assertEqual(ims_patch["ifc_path"], "default_ifc.xml")

    def test_unresolvable_auc_id_raises(self) -> None:
        router = _PyhssRouter()
        router.add("PUT", "/auc/", body="{}")
        router.add("GET", f"/auc/imsi/{self.IMSI}", body="{}")
        with mock.patch.object(urllib.request, "urlopen", side_effect=router):
            with self.assertRaises(RuntimeError) as ctx:
                self.manager._provision_pyhss_subscriber(
                    imsi=self.IMSI,
                    msisdn=self.MSISDN,
                    key=self.KEY,
                    opc=self.OPC,
                    amf=self.AMF,
                )
        self.assertIn("auc_id", str(ctx.exception))

    def test_unreachable_pyhss_raises(self) -> None:
        router = _PyhssRouter()
        router.add("PUT", "/auc/", error=urllib.error.URLError("connection refused"))
        router.add(
            "GET",
            f"/auc/imsi/{self.IMSI}",
            error=urllib.error.URLError("connection refused"),
        )
        with mock.patch.object(urllib.request, "urlopen", side_effect=router):
            with self.assertRaises(RuntimeError) as ctx:
                self.manager._provision_pyhss_subscriber(
                    imsi=self.IMSI,
                    msisdn=self.MSISDN,
                    key=self.KEY,
                    opc=self.OPC,
                    amf=self.AMF,
                )
        self.assertIn("connection refused", str(ctx.exception))


class EnsurePyhssApnsTests(InfraManagerTestCase):
    def test_upserts_internet_and_ims_apns(self) -> None:
        manager = self.make_manager()
        router = _PyhssRouter()
        router.add("PUT", "/apn/")
        router.add("PUT", "/apn/")
        with mock.patch.object(urllib.request, "urlopen", side_effect=router):
            manager._ensure_pyhss_apns()
        payloads = router.sent_payloads("PUT", "/apn/")
        self.assertEqual(
            [p["apn"] for p in payloads],
            ["internet", "ims"],
        )


class ProvisionSubscribersWiringTests(InfraManagerTestCase):
    def test_provision_subscribers_wires_keys_and_all_pyhss_rows(self) -> None:
        manager = self.make_manager()
        run, _calls = _install_fake_run()
        router = _PyhssRouter()
        router.add("PUT", "/apn/")
        router.add("PUT", "/apn/")
        router.add("PUT", "/auc/", body=json.dumps({"auc_id": 11}))
        router.add("PUT", "/subscriber/")
        router.add("PUT", "/ims_subscriber/")
        with (
            mock.patch.object(subprocess, "run", side_effect=run),
            mock.patch.object(urllib.request, "urlopen", side_effect=router),
        ):
            manager.provision_subscribers(
                1,
                key="AABBCCDDEEFF00112233445566778899",
                opc="112233445566778899AABBCCDDEEFF00",
            )
        auc_payload = router.sent_payloads("PUT", "/auc/")[0]
        self.assertEqual(auc_payload["ki"], "AABBCCDDEEFF00112233445566778899")
        self.assertEqual(auc_payload["opc"], "112233445566778899AABBCCDDEEFF00")
        paths = router.request_paths()
        self.assertIn(("PUT", "/subscriber/"), paths)
        self.assertIn(("PUT", "/ims_subscriber/"), paths)


if __name__ == "__main__":
    unittest.main()
