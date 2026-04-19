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
