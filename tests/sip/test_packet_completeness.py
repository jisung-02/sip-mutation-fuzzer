import unittest

from volte_mutation_fuzzer.generator import GeneratorSettings, RequestSpec, SIPGenerator
from volte_mutation_fuzzer.sip import SIPMethod
from volte_mutation_fuzzer.sip.completeness import (
    GENERATOR_COMPLETE_METHODS,
    PACKET_COMPLETENESS,
    RUNTIME_COMPLETE_METHODS,
    PacketCompletionTier,
    get_packet_completion,
)
from volte_mutation_fuzzer.sip.requests import REQUEST_MODELS_BY_METHOD
from volte_mutation_fuzzer.dialog.scenarios import scenario_for_method


class PacketCompletenessTests(unittest.TestCase):
    def test_registry_covers_every_request_method(self) -> None:
        self.assertEqual(set(PACKET_COMPLETENESS), set(REQUEST_MODELS_BY_METHOD))
        self.assertEqual(
            len(PACKET_COMPLETENESS),
            len(REQUEST_MODELS_BY_METHOD),
        )

    def test_expected_method_completion_matrix_matches_plan(self) -> None:
        expected = {
            SIPMethod.INVITE: (
                PacketCompletionTier.runtime_complete,
                "stateless",
                "real_ue_baseline",
            ),
            SIPMethod.ACK: (
                PacketCompletionTier.runtime_complete,
                "invite_ack",
                "invite_dialog",
            ),
            SIPMethod.BYE: (
                PacketCompletionTier.runtime_complete,
                "invite_dialog",
                "invite_dialog",
            ),
            SIPMethod.CANCEL: (
                PacketCompletionTier.runtime_complete,
                "invite_cancel",
                "invite_dialog",
            ),
            SIPMethod.INFO: (
                PacketCompletionTier.runtime_complete,
                "invite_dialog",
                "invite_dialog",
            ),
            SIPMethod.MESSAGE: (
                PacketCompletionTier.runtime_complete,
                "stateless",
                "stateless",
            ),
            SIPMethod.NOTIFY: (
                PacketCompletionTier.generator_complete,
                "unsupported",
                "generator_only",
            ),
            SIPMethod.OPTIONS: (
                PacketCompletionTier.runtime_complete,
                "stateless",
                "stateless",
            ),
            SIPMethod.PRACK: (
                PacketCompletionTier.runtime_complete,
                "invite_prack",
                "invite_dialog",
            ),
            SIPMethod.PUBLISH: (
                PacketCompletionTier.generator_complete,
                "unsupported",
                "generator_only",
            ),
            SIPMethod.REFER: (
                PacketCompletionTier.runtime_complete,
                "invite_dialog",
                "invite_dialog",
            ),
            SIPMethod.REGISTER: (
                PacketCompletionTier.generator_complete,
                "unsupported",
                "generator_only",
            ),
            SIPMethod.SUBSCRIBE: (
                PacketCompletionTier.runtime_complete,
                "stateless",
                "stateless",
            ),
            SIPMethod.UPDATE: (
                PacketCompletionTier.runtime_complete,
                "invite_dialog",
                "invite_dialog",
            ),
        }

        for method, (tier, runtime_path, baseline_scope) in expected.items():
            completion = get_packet_completion(method)
            self.assertEqual(completion.tier, tier)
            self.assertEqual(completion.runtime_path.value, runtime_path)
            self.assertEqual(completion.baseline_scope.value, baseline_scope)

    def test_runtime_complete_methods_have_honest_runtime_paths(self) -> None:
        self.assertEqual(
            set(RUNTIME_COMPLETE_METHODS),
            {
                SIPMethod.INVITE,
                SIPMethod.ACK,
                SIPMethod.BYE,
                SIPMethod.CANCEL,
                SIPMethod.INFO,
                SIPMethod.MESSAGE,
                SIPMethod.SUBSCRIBE,
                SIPMethod.OPTIONS,
                SIPMethod.PRACK,
                SIPMethod.REFER,
                SIPMethod.UPDATE,
            },
        )

        for method in RUNTIME_COMPLETE_METHODS:
            completion = get_packet_completion(method)
            scenario = scenario_for_method(method.value)
            if completion.runtime_path.value == "stateless":
                self.assertIsNone(scenario)
            else:
                self.assertIsNotNone(scenario)
                self.assertEqual(scenario.scenario_type.value, completion.runtime_path.value)

    def test_generator_complete_methods_render_without_overrides(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        self.assertEqual(
            set(GENERATOR_COMPLETE_METHODS),
            {
                SIPMethod.NOTIFY,
                SIPMethod.PUBLISH,
                SIPMethod.REGISTER,
            },
        )

        for method in GENERATOR_COMPLETE_METHODS:
            completion = get_packet_completion(method)
            self.assertEqual(completion.runtime_path.value, "unsupported")
            packet = generator.generate_request(RequestSpec(method=method))
            self.assertEqual(packet.method, method)
