from __future__ import annotations

import unittest

from volte_mutation_fuzzer.generator import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
    SIPGenerator,
)
from volte_mutation_fuzzer.mutator.contracts import (
    MutatedCase,
    MutationConfig,
    MutationRecord,
    MutationTarget,
)
from volte_mutation_fuzzer.sip.common import SIPMethod


class MutatorContractTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.generator = SIPGenerator(GeneratorSettings())

    def build_request(self):
        return self.generator.generate_request(RequestSpec(method=SIPMethod.OPTIONS))

    def build_response(self):
        context = DialogContext(
            call_id="call-1",
            local_tag="ue-tag",
            local_cseq=7,
        )
        return self.generator.generate_response(
            ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
            context,
        )


class MutationConfigTests(MutatorContractTestCase):
    def test_defaults_match_minimal_mutator_contract(self) -> None:
        config = MutationConfig()

        self.assertIsNone(config.seed)
        self.assertEqual(config.strategy, "default")
        self.assertEqual(config.layer, "auto")
        self.assertEqual(config.max_operations, 1)
        self.assertTrue(config.preserve_valid_model)

    def test_normalizes_strategy_and_rejects_invalid_values(self) -> None:
        config = MutationConfig(strategy=" state_breaker ")
        self.assertEqual(config.strategy, "state_breaker")

        with self.assertRaises(ValueError):
            MutationConfig(strategy="   ")

        with self.assertRaises(ValueError):
            MutationConfig.model_validate({"layer": "unknown"})

        with self.assertRaises(ValueError):
            MutationConfig(max_operations=0)


class MutationTargetTests(MutatorContractTestCase):
    def test_normalizes_explicit_target_shape(self) -> None:
        target = MutationTarget(
            layer="model",
            path=" call_id ",
            alias=" Call-ID ",
            operator_hint=" replace ",
        )

        self.assertEqual(target.layer, "model")
        self.assertEqual(target.path, "call_id")
        self.assertEqual(target.alias, "Call-ID")
        self.assertEqual(target.operator_hint, "replace")

    def test_rejects_blank_target_path(self) -> None:
        with self.assertRaises(ValueError):
            MutationTarget(layer="wire", path="   ")


class MutationRecordTests(MutatorContractTestCase):
    def test_records_operator_target_and_before_after_values(self) -> None:
        record = MutationRecord(
            layer="wire",
            target=MutationTarget(layer="wire", path="header:Call-ID"),
            operator=" delete_header ",
            before="Call-ID: call-1",
            after=None,
            note=" removed duplicate header ",
        )

        payload = record.model_dump()
        self.assertEqual(payload["layer"], "wire")
        self.assertEqual(payload["operator"], "delete_header")
        self.assertEqual(payload["target"]["path"], "header:Call-ID")
        self.assertEqual(payload["before"], "Call-ID: call-1")
        self.assertIsNone(payload["after"])
        self.assertEqual(payload["note"], "removed duplicate header")

    def test_rejects_record_target_layer_mismatch(self) -> None:
        with self.assertRaises(ValueError):
            MutationRecord(
                layer="byte",
                target=MutationTarget(layer="wire", path="header:Call-ID"),
                operator="truncate",
            )


class MutatedCaseTests(MutatorContractTestCase):
    def test_accepts_model_layer_results(self) -> None:
        original_packet = self.build_request()
        mutated_packet = original_packet.model_copy(update={"call_id": "call-2"})
        record = MutationRecord(
            layer="model",
            target=MutationTarget(layer="model", path="call_id"),
            operator="replace_value",
            before="call-1",
            after="call-2",
        )

        case = MutatedCase(
            original_packet=original_packet,
            mutated_packet=mutated_packet,
            records=(record,),
            seed=17,
            strategy=" state_breaker ",
            final_layer="model",
        )

        self.assertEqual(case.strategy, "state_breaker")
        self.assertEqual(case.final_layer, "model")
        mutated_packet = case.mutated_packet
        assert mutated_packet is not None
        self.assertEqual(mutated_packet.call_id, "call-2")
        self.assertEqual(case.records[0].target.path, "call_id")

    def test_accepts_wire_layer_results_without_mutated_packet(self) -> None:
        original_packet = self.build_request()

        case = MutatedCase(
            original_packet=original_packet,
            wire_text="OPTIONS sip:ue@example.com SIP/2.0\r\nCall-ID: broken\r\n\r\n",
            final_layer="wire",
        )

        self.assertEqual(case.final_layer, "wire")
        self.assertIsNone(case.mutated_packet)
        wire_text = case.wire_text
        assert wire_text is not None
        self.assertIn("Call-ID: broken", wire_text)

    def test_accepts_byte_layer_results(self) -> None:
        original_packet = self.build_response()

        case = MutatedCase(
            original_packet=original_packet,
            packet_bytes=b"SIP/2.0 200 OK\r\n\xff\r\n",
            final_layer="byte",
        )

        self.assertEqual(case.final_layer, "byte")
        self.assertEqual(case.packet_bytes, b"SIP/2.0 200 OK\r\n\xff\r\n")

    def test_requires_matching_artifact_for_final_layer(self) -> None:
        original_packet = self.build_request()

        with self.assertRaises(ValueError):
            MutatedCase(original_packet=original_packet, final_layer="wire")

    def test_rejects_unknown_fields(self) -> None:
        original_packet = self.build_request()

        with self.assertRaises(ValueError):
            MutatedCase.model_validate(
                {
                    "original_packet": original_packet,
                    "mutated_packet": original_packet,
                    "final_layer": "model",
                    "unexpected": True,
                }
            )


if __name__ == "__main__":
    unittest.main()
