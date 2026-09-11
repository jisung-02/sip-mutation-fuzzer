import tempfile
import unittest
import unittest.mock
from types import SimpleNamespace

from volte_mutation_fuzzer.campaign.contracts import CampaignConfig, CaseSpec
from volte_mutation_fuzzer.campaign.core import CampaignExecutor
from volte_mutation_fuzzer.dialog.contracts import (
    SequenceExchangeResult,
    SequenceStepResult,
)
from volte_mutation_fuzzer.sender.contracts import (
    SendReceiveResult,
    SocketObservation,
    TargetEndpoint,
)


def _sequence_config(**overrides) -> CampaignConfig:
    defaults = dict(
        mode="real-ue-direct",
        target_host="10.20.20.8",
        target_msisdn="111111",
        methods=("INVITE",),
        layers=("wire",),
        strategies=("identity",),
        sequence_scenario="invite_retransmit",
        sequence_repeats=2,
        max_cases=1,
    )
    defaults.update(overrides)
    return CampaignConfig(**defaults)


def _step_result(step_index: int, method: str, *, mutate: bool = False):
    return SequenceStepResult(
        step_index=step_index,
        method=method,
        mutate=mutate,
        success=True,
        send_result=SendReceiveResult(
            target=TargetEndpoint(
                host="10.20.20.8",
                port=8100,
                mode="real-ue-direct",
                msisdn="111111",
                ipsec_mode="null",
                bind_container="pcscf",
            ),
            artifact_kind="wire",
            bytes_sent=100,
            outcome="success",
            responses=(
                SocketObservation(
                    status_code=200,
                    reason_phrase="OK",
                    raw_text="SIP/2.0 200 OK\r\n\r\n",
                    classification="success",
                ),
            ),
            send_started_at=1.0,
            send_completed_at=1.1,
        ),
    )


class SequenceConfigTests(unittest.TestCase):
    def test_valid_config_passes(self) -> None:
        config = _sequence_config()
        self.assertEqual(config.sequence_scenario, "invite_retransmit")
        self.assertEqual(config.sequence_repeats, 2)

    def test_unknown_scenario_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown sequence scenario"):
            _sequence_config(sequence_scenario="nope")

    def test_mutually_exclusive_with_mt(self) -> None:
        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            _sequence_config(mt=True)

    def test_rejects_response_codes(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not support response_codes"):
            _sequence_config(response_codes=(180,))

    def test_requires_invite_methods(self) -> None:
        with self.assertRaisesRegex(ValueError, "--methods INVITE only"):
            _sequence_config(methods=("OPTIONS",))


class SequenceExecutionTests(unittest.TestCase):
    def _build_executor(self, **overrides) -> CampaignExecutor:
        config = _sequence_config(**overrides)
        with tempfile.TemporaryDirectory(suffix="vmf-results") as tmp:
            return CampaignExecutor(config.model_copy(update={"results_dir": tmp}))

    def test_execute_case_dispatches_to_sequence_path(self) -> None:
        executor = self._build_executor()
        spec = CaseSpec(
            case_id=0, seed=0, method="INVITE", layer="wire", strategy="identity"
        )
        with unittest.mock.patch.object(
            executor, "_execute_sequence_case"
        ) as sequence_spy:
            sequence_spy.return_value = None
            executor._execute_case(spec)
            sequence_spy.assert_called_once()

    def test_sequence_case_reports_verdict_and_step_details(self) -> None:
        executor = self._build_executor()
        spec = CaseSpec(
            case_id=0, seed=0, method="INVITE", layer="wire", strategy="identity"
        )
        exchange = SequenceExchangeResult(
            scenario_name="invite_retransmit",
            step_results=(
                _step_result(0, "INVITE", mutate=True),
                _step_result(0, "INVITE", mutate=True),
                _step_result(1, "CANCEL"),
            ),
            succeeded=True,
        )

        with (
            unittest.mock.patch(
                "volte_mutation_fuzzer.campaign.core.DialogOrchestrator"
            ) as orchestrator_cls,
            unittest.mock.patch.object(
                executor._oracle,
                "evaluate",
                return_value=SimpleNamespace(
                    verdict="suspicious",
                    reason="4xx response",
                    response_code=400,
                    elapsed_ms=10.0,
                    process_alive=True,
                    details={},
                ),
            ),
            unittest.mock.patch.object(
                executor,
                "_persist_case_artifacts",
                side_effect=lambda _spec, case_result, **_kwargs: case_result,
            ),
        ):
            orchestrator_cls.return_value.execute_sequence.return_value = exchange
            result = executor._execute_case(spec)

        self.assertEqual(result.verdict, "suspicious")
        self.assertIn("sequence:invite_retransmit", result.mutation_ops)
        steps = result.details["sequence_steps"]
        self.assertEqual(len(steps), 3)
        self.assertEqual(steps[0]["method"], "INVITE")
        self.assertTrue(steps[0]["mutate"])
        self.assertIn("--scenario invite_retransmit", result.reproduction_cmd)
        self.assertIn("--repeats 2", result.reproduction_cmd)

    def test_failed_sequence_step_reports_unknown(self) -> None:
        executor = self._build_executor()
        spec = CaseSpec(
            case_id=0, seed=0, method="INVITE", layer="wire", strategy="identity"
        )
        exchange = SequenceExchangeResult(
            scenario_name="invite_retransmit",
            step_results=(
                SequenceStepResult(
                    step_index=0,
                    method="INVITE",
                    mutate=True,
                    success=False,
                    error="no response",
                ),
            ),
            succeeded=False,
            error="no response",
        )
        with unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.DialogOrchestrator"
        ) as orchestrator_cls:
            orchestrator_cls.return_value.execute_sequence.return_value = exchange
            result = executor._execute_case(spec)

        self.assertEqual(result.verdict, "unknown")
        self.assertIn("sequence step failed", result.reason)
        self.assertEqual(result.details["sequence_scenario"], "invite_retransmit")


if __name__ == "__main__":
    unittest.main()
