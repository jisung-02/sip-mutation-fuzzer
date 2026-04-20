import tempfile
import unittest

from volte_mutation_fuzzer.campaign.contracts import CampaignConfig, CaseSpec
from volte_mutation_fuzzer.campaign.core import CampaignExecutor
from tests.dialog._dialog_server import (
    DialogUDPResponder,
    make_200_ok,
    make_200_ok_generic,
    make_486_busy,
)


class CampaignDialogIntegrationTests(unittest.TestCase):
    @staticmethod
    def _make_183_session_progress(*, reliable: bool = False, rseq: int = 73) -> bytes:
        reliable_headers = ""
        if reliable:
            reliable_headers = f"Require: 100rel\r\nRSeq: {rseq}\r\n"
        return (
            "SIP/2.0 183 Session Progress\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKtest\r\n"
            "From: <sip:remote@ims.mnc001.mcc001.3gppnetwork.org>;tag=uac-tag\r\n"
            "To: <sip:111111@ims.mnc001.mcc001.3gppnetwork.org>;tag=early-183\r\n"
            "Call-ID: a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org\r\n"
            "CSeq: 41 INVITE\r\n"
            "Contact: <sip:111111@127.0.0.1:5070;transport=udp>\r\n"
            "Record-Route: <sip:pcscf1.ims.mnc001.mcc001.3gppnetwork.org;lr>,"
            "<sip:pcscf2.ims.mnc001.mcc001.3gppnetwork.org;lr>\r\n"
            f"{reliable_headers}"
            "Content-Length: 0\r\n"
            "\r\n"
        ).encode("utf-8")

    def _make_config(self, host: str, port: int, **kwargs) -> CampaignConfig:
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)

        defaults = dict(
            target_host=host,
            target_port=port,
            methods=("BYE",),
            layers=("model",),
            strategies=("default",),
            max_cases=1,
            timeout_seconds=1.0,
            cooldown_seconds=0.0,
            check_process=False,
            results_dir=tmpdir.name, output_name="test",
        )
        defaults.update(kwargs)
        return CampaignConfig.model_validate(defaults)

    @staticmethod
    def _make_case_spec(method: str) -> CaseSpec:
        return CaseSpec(
            case_id=0,
            seed=123,
            method=method,
            layer="model",
            strategy="default",
        )

    @staticmethod
    def _methods_seen(server: DialogUDPResponder) -> list[str]:
        methods: list[str] = []
        for payload in server.received_payloads:
            first_line = payload.split(b"\r\n", 1)[0].decode(
                "utf-8", errors="replace"
            )
            methods.append(first_line.split(" ", 1)[0])
        return methods

    def test_execute_case_routes_bye_through_dialog_orchestrator(self) -> None:
        server = DialogUDPResponder(
            responses_by_method={
                "INVITE": make_200_ok(),
                "ACK": b"",
                "BYE": make_200_ok_generic("BYE"),
            }
        )
        server.start()
        self.addCleanup(server.close)

        executor = CampaignExecutor(self._make_config(server.host, server.port))

        result = executor._execute_case(self._make_case_spec("BYE"))

        self.assertNotEqual(result.verdict, "unknown")
        self.assertIn("INVITE", self._methods_seen(server))
        self.assertIn("BYE", self._methods_seen(server))

    def test_execute_case_returns_unknown_when_dialog_setup_fails(self) -> None:
        server = DialogUDPResponder(
            responses_by_method={"INVITE": make_486_busy()}
        )
        server.start()
        self.addCleanup(server.close)

        executor = CampaignExecutor(self._make_config(server.host, server.port))

        result = executor._execute_case(self._make_case_spec("BYE"))

        self.assertEqual(result.verdict, "unknown")
        self.assertIn("dialog setup failed", result.reason)
        self.assertEqual(self._methods_seen(server), ["INVITE"])

    def test_execute_case_keeps_options_on_stateless_path(self) -> None:
        server = DialogUDPResponder(
            responses_by_method={"OPTIONS": make_200_ok_generic("OPTIONS")}
        )
        server.start()
        self.addCleanup(server.close)

        executor = CampaignExecutor(
            self._make_config(server.host, server.port, methods=("OPTIONS",))
        )

        result = executor._execute_case(self._make_case_spec("OPTIONS"))

        self.assertNotEqual(result.verdict, "unknown")
        self.assertEqual(self._methods_seen(server), ["OPTIONS"])

    def test_execute_case_keeps_subscribe_on_stateless_path(self) -> None:
        server = DialogUDPResponder(
            responses_by_method={"SUBSCRIBE": make_200_ok_generic("SUBSCRIBE")}
        )
        server.start()
        self.addCleanup(server.close)

        executor = CampaignExecutor(
            self._make_config(server.host, server.port, methods=("SUBSCRIBE",))
        )

        result = executor._execute_case(self._make_case_spec("SUBSCRIBE"))

        self.assertNotEqual(result.verdict, "unknown")
        self.assertEqual(self._methods_seen(server), ["SUBSCRIBE"])

    def test_execute_case_routes_prack_through_early_dialog_path(self) -> None:
        server = DialogUDPResponder(
            responses_by_method={
                "INVITE": self._make_183_session_progress(reliable=True, rseq=73),
                "PRACK": make_200_ok_generic("PRACK"),
            }
        )
        server.start()
        self.addCleanup(server.close)

        executor = CampaignExecutor(
            self._make_config(server.host, server.port, methods=("PRACK",))
        )

        result = executor._execute_case(self._make_case_spec("PRACK"))

        self.assertNotEqual(result.verdict, "unknown")
        self.assertEqual(self._methods_seen(server), ["INVITE", "PRACK"])
        prack_payload = server.received_payloads[-1].decode("utf-8", errors="replace")
        self.assertIn("PRACK sip:111111@127.0.0.1:5070", prack_payload)
        self.assertIn("To: \"UE\" <sip:111111@ims.mnc001.mcc001.3gppnetwork.org>;tag=early-183", prack_payload)
        self.assertIn("RAck: 73 41 INVITE", prack_payload)
        self.assertIn(
            "Route: sip:pcscf2.ims.mnc001.mcc001.3gppnetwork.org;lr",
            prack_payload,
        )

    def test_execute_case_rejects_non_reliable_prack_setup(self) -> None:
        server = DialogUDPResponder(
            responses_by_method={
                "INVITE": self._make_183_session_progress(reliable=False),
            }
        )
        server.start()
        self.addCleanup(server.close)

        executor = CampaignExecutor(
            self._make_config(server.host, server.port, methods=("PRACK",))
        )

        result = executor._execute_case(self._make_case_spec("PRACK"))

        self.assertEqual(result.verdict, "unknown")
        self.assertIn("dialog setup failed", result.reason)
        self.assertEqual(self._methods_seen(server), ["INVITE"])

    def test_execute_case_routes_info_through_dialog_path(self) -> None:
        server = DialogUDPResponder(
            responses_by_method={
                "INVITE": make_200_ok(contact="sip:111111@127.0.0.1:5071"),
                "ACK": b"",
                "INFO": make_200_ok_generic("INFO"),
                "BYE": make_200_ok_generic("BYE"),
            }
        )
        server.start()
        self.addCleanup(server.close)

        executor = CampaignExecutor(
            self._make_config(server.host, server.port, methods=("INFO",))
        )

        result = executor._execute_case(self._make_case_spec("INFO"))

        self.assertNotEqual(result.verdict, "unknown")
        self.assertEqual(self._methods_seen(server), ["INVITE", "ACK", "INFO", "BYE"])
