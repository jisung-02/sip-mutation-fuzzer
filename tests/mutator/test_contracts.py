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

REALISTIC_CALL_ID = "a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_MUTATED_CALL_ID = (
    "b7f2a1d43caa9f1d@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
)
REALISTIC_LOCAL_TAG = "9fxced76sl"
REALISTIC_OPTIONS_WIRE = (
    "OPTIONS sip:001010000123511@10.20.20.8:8100 SIP/2.0\r\n"
    f"Call-ID: {REALISTIC_CALL_ID}\r\n\r\n"
)


class MutatorContractTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.generator = SIPGenerator(GeneratorSettings())

    def build_request(self):
        return self.generator.generate_request(RequestSpec(method=SIPMethod.OPTIONS))

    def build_response(self):
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            local_cseq=7,
        )
        return self.generator.generate_response(
            ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
            context,
        )


class MutationConfigTests(MutatorContractTestCase):
    def test_defaults_match_minimal_mutator_contract(self) -> None:
        config = MutationConfig()
        payload = config.model_dump(mode="json")

        self.assertIsNone(config.seed)
        self.assertEqual(config.strategy, "default")
        self.assertEqual(config.layer, "auto")
        self.assertEqual(config.max_operations, 1)
        self.assertTrue(config.preserve_valid_model)
        self.assertEqual(
            set(payload),
            {
                "seed",
                "strategy",
                "layer",
                "max_operations",
                "preserve_valid_model",
            },
        )

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

    def test_normalizes_blank_alias_and_operator_hint_to_none(self) -> None:
        target = MutationTarget(
            layer="wire",
            path=" header:Call-ID ",
            alias="   ",
            operator_hint="   ",
        )

        self.assertEqual(target.path, "header:Call-ID")
        self.assertIsNone(target.alias)
        self.assertIsNone(target.operator_hint)

    def test_rejects_blank_target_path(self) -> None:
        with self.assertRaises(ValueError):
            MutationTarget(layer="wire", path="   ")


class MutationRecordTests(MutatorContractTestCase):
    def test_serializes_operator_target_and_before_after_values(self) -> None:
        record = MutationRecord(
            layer="wire",
            target=MutationTarget(layer="wire", path="header:Call-ID"),
            operator=" delete_header ",
            before=f"Call-ID: {REALISTIC_CALL_ID}",
            after=None,
            note=" removed duplicate header ",
        )

        payload = record.model_dump(mode="json", exclude_none=True)
        self.assertEqual(payload["layer"], "wire")
        self.assertEqual(payload["operator"], "delete_header")
        self.assertEqual(payload["target"]["path"], "header:Call-ID")
        self.assertEqual(payload["before"], f"Call-ID: {REALISTIC_CALL_ID}")
        self.assertEqual(payload["note"], "removed duplicate header")
        self.assertNotIn("after", payload)
        self.assertEqual(payload["target"], {"layer": "wire", "path": "header:Call-ID"})

    def test_rejects_record_target_layer_mismatch(self) -> None:
        with self.assertRaises(ValueError):
            MutationRecord(
                layer="byte",
                target=MutationTarget(layer="wire", path="header:Call-ID"),
                operator="truncate",
            )


class MutatedCaseTests(MutatorContractTestCase):
    def test_model_layer_serializes_packets_records_and_aliases(self) -> None:
        original_packet = self.build_request()
        mutated_packet = original_packet.model_copy(
            update={"call_id": REALISTIC_MUTATED_CALL_ID}
        )
        record = MutationRecord(
            layer="model",
            target=MutationTarget(layer="model", path="call_id"),
            operator="replace_value",
            before=REALISTIC_CALL_ID,
            after=REALISTIC_MUTATED_CALL_ID,
        )

        case = MutatedCase(
            original_packet=original_packet,
            mutated_packet=mutated_packet,
            records=(record,),
            seed=17,
            strategy=" state_breaker ",
            final_layer="model",
        )
        payload = case.model_dump(mode="json", by_alias=True, exclude_none=True)

        self.assertEqual(case.strategy, "state_breaker")
        self.assertEqual(case.final_layer, "model")
        mutated_packet = case.mutated_packet
        assert mutated_packet is not None
        self.assertEqual(mutated_packet.call_id, REALISTIC_MUTATED_CALL_ID)
        self.assertEqual(case.records[0].target.path, "call_id")
        self.assertEqual(payload["final_layer"], "model")
        self.assertEqual(payload["seed"], 17)
        self.assertEqual(payload["strategy"], "state_breaker")
        self.assertEqual(payload["mutated_packet"]["call_id"], REALISTIC_MUTATED_CALL_ID)
        self.assertIn("from", payload["original_packet"])
        self.assertNotIn("from_", payload["original_packet"])
        self.assertEqual(payload["records"][0]["target"]["path"], "call_id")
        self.assertNotIn("wire_text", payload)
        self.assertNotIn("packet_bytes", payload)

    def test_wire_layer_serializes_wire_artifact_only(self) -> None:
        original_packet = self.build_request()

        case = MutatedCase(
            original_packet=original_packet,
            wire_text=REALISTIC_OPTIONS_WIRE,
            final_layer="wire",
        )
        payload = case.model_dump(mode="json", by_alias=True, exclude_none=True)

        self.assertEqual(case.final_layer, "wire")
        self.assertIsNone(case.mutated_packet)
        wire_text = case.wire_text
        assert wire_text is not None
        self.assertIn(f"Call-ID: {REALISTIC_CALL_ID}", wire_text)
        self.assertEqual(payload["final_layer"], "wire")
        self.assertEqual(payload["wire_text"], REALISTIC_OPTIONS_WIRE)
        self.assertEqual(payload["records"], [])
        self.assertNotIn("mutated_packet", payload)
        self.assertNotIn("packet_bytes", payload)

    def test_byte_layer_serializes_ascii_packet_bytes(self) -> None:
        original_packet = self.build_response()

        case = MutatedCase(
            original_packet=original_packet,
            packet_bytes=b"SIP/2.0 200 OK\r\n\r\n",
            final_layer="byte",
        )
        payload = case.model_dump(mode="json", by_alias=True, exclude_none=True)

        self.assertEqual(case.final_layer, "byte")
        self.assertEqual(case.packet_bytes, b"SIP/2.0 200 OK\r\n\r\n")
        self.assertEqual(payload["final_layer"], "byte")
        self.assertEqual(payload["packet_bytes"], "SIP/2.0 200 OK\r\n\r\n")
        self.assertNotIn("mutated_packet", payload)
        self.assertNotIn("wire_text", payload)

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
