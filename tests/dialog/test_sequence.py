import unittest
import unittest.mock

from volte_mutation_fuzzer.dialog.contracts import (
    DialogStepResult,
    SequenceScenario,
    SequenceStep,
)
from volte_mutation_fuzzer.dialog.core import DialogOrchestrator
from volte_mutation_fuzzer.dialog.sequence_catalog import (
    SEQUENCE_SCENARIO_NAMES,
    build_sequence_scenario,
)
from volte_mutation_fuzzer.generator.contracts import GeneratorSettings
from volte_mutation_fuzzer.generator.core import SIPGenerator
from volte_mutation_fuzzer.mutator.contracts import MutationConfig
from volte_mutation_fuzzer.mutator.core import SIPMutator
from volte_mutation_fuzzer.sender.contracts import TargetEndpoint


def _step_result(step_index: int, method: str, *, success: bool = True):
    return DialogStepResult(
        step_index=step_index,
        method=method,
        role="send",
        success=success,
        error=None if success else "boom",
    )


class SequenceCatalogTests(unittest.TestCase):
    def test_names_are_cataloged(self) -> None:
        self.assertEqual(
            SEQUENCE_SCENARIO_NAMES,
            (
                "cancel_retransmit",
                "invite_double_bye",
                "invite_early_bye",
                "invite_retransmit",
            ),
        )

    def test_every_scenario_has_mutated_and_cleanup_steps(self) -> None:
        for name in SEQUENCE_SCENARIO_NAMES:
            scenario = build_sequence_scenario(name)
            self.assertTrue(any(step.mutate for step in scenario.steps), name)
            # cleanup: every INVITE-bearing scenario must end with CANCEL/BYE
            if any(step.method == "INVITE" for step in scenario.steps):
                self.assertIn(scenario.steps[-1].method, {"CANCEL", "BYE"}, name)

    def test_repeat_override_only_touches_repeated_steps(self) -> None:
        scenario = build_sequence_scenario("invite_retransmit", repeat_override=5)
        methods_repeats = [(step.method, step.repeat) for step in scenario.steps]
        self.assertEqual(methods_repeats, [("INVITE", 5), ("CANCEL", 1)])

    def test_unknown_name_raises_with_available_list(self) -> None:
        with self.assertRaisesRegex(ValueError, "invite_retransmit"):
            build_sequence_scenario("does_not_exist")

    def test_invalid_repeat_override_is_ignored(self) -> None:
        scenario = build_sequence_scenario("invite_retransmit", repeat_override=0)
        self.assertEqual(scenario.steps[0].repeat, 2)


class ExecuteSequenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.orchestrator = DialogOrchestrator(
            SIPGenerator(GeneratorSettings()),
            SIPMutator(),
            TargetEndpoint(host="127.0.0.1", port=15060, mode="softphone"),
        )
        self.config = MutationConfig(seed=1, layer="wire")

    def _run(self, scenario: SequenceScenario, step_results):
        calls: list[dict[str, object]] = []

        def _fake_run_step(sock, step, step_index, context, *, mutation_config):
            calls.append(
                {
                    "method": step.method,
                    "is_fuzz_target": step.is_fuzz_target,
                    "mutation": mutation_config is not None,
                }
            )
            return step_results.pop(0)

        with unittest.mock.patch.object(
            self.orchestrator, "_run_step", side_effect=_fake_run_step
        ):
            return self.orchestrator.execute_sequence(scenario, self.config), calls

    def test_repeat_sends_step_n_times(self) -> None:
        scenario = SequenceScenario(
            name="t",
            steps=(SequenceStep(method="INVITE", mutate=True, repeat=3),),
        )
        step_results = [_step_result(0, "INVITE") for _ in range(3)]
        exchange, calls = self._run(scenario, step_results)

        self.assertTrue(exchange.succeeded)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(exchange.step_results), 3)
        self.assertEqual(
            [result.repeat_index for result in exchange.step_results], [0, 1, 2]
        )

    def test_mutation_only_on_mutate_flagged_steps(self) -> None:
        scenario = SequenceScenario(
            name="t",
            steps=(
                SequenceStep(method="INVITE"),
                SequenceStep(method="BYE", mutate=True),
            ),
        )
        _, calls = self._run(
            scenario, [_step_result(0, "INVITE"), _step_result(1, "BYE")]
        )
        self.assertEqual([call["mutation"] for call in calls], [False, True])

    def test_failed_step_short_circuits_scenario(self) -> None:
        scenario = SequenceScenario(
            name="t",
            steps=(
                SequenceStep(method="INVITE"),
                SequenceStep(method="BYE", mutate=True),
            ),
        )
        exchange, calls = self._run(
            scenario,
            [_step_result(0, "INVITE", success=False), _step_result(1, "BYE")],
        )
        self.assertFalse(exchange.succeeded)
        self.assertEqual(len(calls), 1)  # BYE never sent
        self.assertEqual(exchange.error, "boom")

    def test_scenario_without_mutation_flag_runs_all_steps(self) -> None:
        scenario = SequenceScenario(
            name="t",
            steps=(
                SequenceStep(method="INVITE", mutate=True),
                SequenceStep(method="CANCEL"),
            ),
        )
        exchange, calls = self._run(
            scenario,
            [_step_result(0, "INVITE"), _step_result(1, "CANCEL")],
        )
        self.assertTrue(exchange.succeeded)
        self.assertEqual([call["method"] for call in calls], ["INVITE", "CANCEL"])


if __name__ == "__main__":
    unittest.main()
